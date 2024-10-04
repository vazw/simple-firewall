#![allow(unreachable_code)]
pub mod helper;

use std::net::Ipv4Addr;
use std::time::Instant;

use helper::*;

use anyhow::Ok;
use aya::maps::{HashMap, RingBuf};
use aya::programs::{tc, SchedClassifier, TcAttachType, Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use figment::{
    providers::{Format, Toml},
    Figment,
};
use log::LevelFilter;
use log::{debug, info, warn};

use log4rs::append::rolling_file::policy::compound::CompoundPolicy;
use log4rs::append::rolling_file::policy::compound::{
    roll::fixed_window::FixedWindowRoller, trigger::size::SizeTrigger,
};
use log4rs::append::rolling_file::RollingFileAppender;

use log4rs::encode::pattern::PatternEncoder;

use log4rs::config::{Appender, Root};
use log4rs::Config;

use nohash_hasher::BuildNoHashHasher;
use simple_firewall_common::{Connection, ConnectionState};
use tokio::io::unix::AsyncFd;
use tokio::signal;
use tokio::time::{interval, Duration};

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();

    let log_line_pattern = "{d(%Y-%m-%d %H:%M:%S)} - {l} - {f} - {m}\n";

    let trigger_size = 2u64.pow(20) * 100; // 100 MiB
    let trigger = Box::new(SizeTrigger::new(trigger_size));

    let roller_pattern = "/var/log/sfw/log_{}.gz";
    let roller_count = 5;
    let roller_base = 1;
    let roller = Box::new(
        FixedWindowRoller::builder()
            .base(roller_base)
            .build(roller_pattern, roller_count)
            .unwrap(),
    );

    let compound_policy = Box::new(CompoundPolicy::new(trigger, roller));

    let log_file = RollingFileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(log_line_pattern)))
        .build("/var/log/sfw/sfw.log", compound_policy)
        .unwrap();

    let config = Config::builder()
        .appender(Appender::builder().build("log_file", Box::new(log_file)))
        .build(
            Root::builder()
                .appender("log_file")
                .build(LevelFilter::Debug),
        )
        .unwrap();

    log4rs::init_config(config)?;

    // Bump the memlock rlimit. This is needed for older kernels that don't use the
    // new memcg based accounting, see https://lwn.net/Articles/837122/
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {}", ret);
    }

    // This will include your eBPF object file as raw bytes at compile-time and load it at
    // runtime. This approach is recommended for most real-world use cases. If you would
    // like to specify the eBPF program at runtime rather than at compile-time, you can
    // reach for `Bpf::load_file` instead.
    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/sfw"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/sfw"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }

    info!("Attaching sfw into XDP map");
    let program: &mut Xdp = bpf
        .program_mut("sfw")
        .expect("function not found")
        .try_into()?;
    program.unload().unwrap_or(());
    program.load()?;
    let xdp_link = {
        let link = program.attach(&opt.iface, XdpFlags::HW_MODE);
        if link.is_ok() {
            link.unwrap()
        } else {
            let link = program.attach(&opt.iface, XdpFlags::DRV_MODE);
            if link.is_ok() {
                link.unwrap()
            } else {
                let link = program.attach(&opt.iface, XdpFlags::default());
                if link.is_ok() {
                    link.unwrap()
                } else {
                    let link = program.attach(&opt.iface, XdpFlags::SKB_MODE);
                    if link.is_ok() {
                        link.unwrap()
                    } else {
                        return Ok(());
                    }
                }
            }
        }
    };

    info!("Attaching sfw_egress in to network traffic control classifier");
    _ = tc::qdisc_add_clsact(&opt.iface);
    let egress_program: &mut SchedClassifier = bpf
        .program_mut("sfw_egress")
        .expect("egress function not found")
        .try_into()?;
    egress_program.load()?;
    let tc_link = egress_program
        .attach(&opt.iface, TcAttachType::Egress)
        .expect("failed to initialize sfw_egress");

    let mut config_len: u16;
    let config = Figment::new().merge(Toml::file(&opt.config));
    // Parse dev env config here too
    let config_: AppConfig = config.extract().unwrap_or(
        Figment::new()
            .merge(Toml::file("./sfwconfig.toml"))
            .extract()?,
    );
    config_len = config_.len();
    _ = load_config(&mut bpf, &config_);

    let ring_buf = RingBuf::try_from(bpf.take_map("NEW").unwrap())?;
    let (tx, rx) = tokio::sync::watch::channel(false);
    let t = tokio::spawn(async move {
        let mut rx = rx.clone();
        let mut async_fd = AsyncFd::new(ring_buf).unwrap();
        let mut interval_2 = interval(Duration::from_millis(25));
        let mut connection_timer: std::collections::HashMap<
            u32,
            Instant,
            BuildNoHashHasher<u32>,
        > = std::collections::HashMap::with_capacity_and_hasher(
            100_000,
            nohash_hasher::BuildNoHashHasher::default(),
        );
        let mut connections: HashMap<_, u32, ConnectionState> =
            HashMap::try_from(bpf.take_map("CONNECTIONS").unwrap())?;

        loop {
            tokio::select! {
                _ = async_fd.readable_mut() => {
                    let mut guard = async_fd.readable_mut().await.unwrap();
                    let rb = guard.get_inner_mut();

                    while let Some(read) = rb.next() {
                        let data = read.as_ptr();
                        let contrack = unsafe { std::ptr::read_unaligned::<Connection>(data as *const Connection) };
                        let idx = contrack.into_session();
                        if let Some(timer) = connection_timer.get_mut(&idx) {
                            *timer = Instant::now();
                        } else {
                            connection_timer.insert(idx, Instant::now());
                            debug!("New timmer added for : {}", Ipv4Addr::from_bits(idx).to_string())
                        }

                    }
                    guard.clear_ready();

                }

                _ = rx.changed() => {
                    if *rx.borrow() {
                        break;
                    }
                }

                // Alternative watcher for bpf program map avoid value moved out
                _ = interval_2.tick() => {
                    let new_config: AppConfig
                        = Figment::new().merge(Toml::file(&opt.config)).extract()?;
                    if new_config.len() != config_len {
                        _ = load_config(&mut bpf, &new_config);
                        config_len = new_config.len();
                    };
                    if !connection_timer.is_empty() {
                        for (k,v) in connection_timer.clone().iter() {
                            if v.elapsed().as_secs() > 90 {
                                if connections.remove(k).is_ok() {
                                    info!("Removed timeout on {}", Ipv4Addr::from_bits(*k).to_string());
                                }
                                connection_timer.remove(k);
                            }
                        }
                    }
                }
            }
        }
        Ok(bpf)
    });

    info!("Waiting for Ctrl-C...");
    signal::ctrl_c().await?;
    // Send exit signal
    tx.send(true).unwrap();
    info!("Clearing task");
    // wait task to done
    let mut bpf = t.await?.expect("bpf returned");
    let program: &mut Xdp = bpf.program_mut("sfw").unwrap().try_into()?;
    if program.detach(xdp_link).is_ok() {
        info!("detached xdp program");
    }
    let program: &mut SchedClassifier =
        bpf.program_mut("sfw_egress").unwrap().try_into()?;
    if program.detach(tc_link).is_ok() {
        info!("detached TC program");
    }
    info!("Exiting...");
    Ok(())
}
