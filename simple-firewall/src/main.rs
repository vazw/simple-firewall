#![allow(unreachable_code)]
use std::net::Ipv4Addr;

use anyhow::Ok;
use aya::maps::{Array, HashMap};
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
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config, Root};
use log4rs::encode::pattern::PatternEncoder;

use serde::Deserialize;
use tokio::signal;
use tokio::time::{interval, Duration};

#[derive(Debug, Clone, Deserialize)]
struct TcpIn {
    pub sport: Option<Vec<u16>>,
    pub dport: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
struct TcpOut {
    pub sport: Option<Vec<u16>>,
    pub dport: Option<Vec<u16>>,
}
#[derive(Debug, Clone, Deserialize)]
struct UdpIn {
    pub sport: Option<Vec<u16>>,
    pub dport: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
struct UdpOut {
    pub sport: Option<Vec<u16>>,
    pub dport: Option<Vec<u16>>,
}

#[derive(Debug, Clone, Deserialize)]
struct AppConfig {
    pub dns: Option<Vec<String>>,
    pub tcp_in: Option<TcpIn>,
    pub tcp_out: Option<TcpOut>,
    pub udp_in: Option<UdpIn>,
    pub udp_out: Option<UdpOut>,
}

impl AppConfig {
    pub fn len(&self) -> u16 {
        let mut len: u16 = 0;
        if let Some(dns) = &self.dns {
            len += dns.len() as u16;
        }
        if let Some(tcp) = &self.tcp_in {
            if let Some(n) = &tcp.sport {
                len += n.len() as u16;
            }
            if let Some(n) = &tcp.dport {
                len += n.len() as u16;
            }
        }
        if let Some(tcp) = &self.tcp_out {
            if let Some(n) = &tcp.sport {
                len += n.len() as u16;
            }
            if let Some(n) = &tcp.dport {
                len += n.len() as u16;
            }
        }
        if let Some(udp) = &self.udp_in {
            if let Some(n) = &udp.sport {
                len += n.len() as u16;
            }
            if let Some(n) = &udp.dport {
                len += n.len() as u16;
            }
        }
        if let Some(udp) = &self.udp_out {
            if let Some(n) = &udp.sport {
                len += n.len() as u16;
            }
            if let Some(n) = &udp.dport {
                len += n.len() as u16;
            }
        }
        len
    }
}

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp1s0")]
    iface: String,
    #[clap(short, long, default_value = "/etc/sfw/sfwconfig.toml")]
    config: String,
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    let logfile = FileAppender::builder()
        .encoder(Box::new(PatternEncoder::new(
            "{d(%Y-%m-%d %H:%M:%S)} - {l} - {f} - {m}\n",
        )))
        .build("/var/log/sfw.log")?;

    let config = Config::builder()
        .appender(Appender::builder().build("logfile", Box::new(logfile)))
        .build(Root::builder().appender("logfile").build(LevelFilter::Info))?;

    log4rs::init_config(config)?;
    // env_logger::init();
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
    // let ring_buf = RingBuf::try_from(
    //     bpf.take_map("CONBUF").expect("CONBUF ringbuffer is exits"),
    // )?;

    let (tx, rx) = tokio::sync::watch::channel(false);
    let t = tokio::spawn(async move {
        let mut rx = rx.clone();
        // let mut async_fd = AsyncFd::new(ring_buf).unwrap();
        let mut interval_2 = interval(Duration::from_millis(10));
        // let mut conn: std::collections::HashMap<u32, Instant> =
        //     std::collections::HashMap::with_capacity(262_144);
        // let mut connections: HashMap<_, u32, ConnectionState> =
        //     HashMap::try_from(bpf.take_map("CONNECTIONS").unwrap())?;

        loop {
            tokio::select! {
                // _ = async_fd.readable_mut() => {
                //     let mut guard = async_fd.readable_mut().await.unwrap();
                //     let rb = guard.get_inner_mut();
                //
                //     while let Some(read) = rb.next() {
                //         let data = read.as_ptr();
                //         let contrack = unsafe { std::ptr::read_unaligned::<Connection>(data as *const Connection) };
                //         debug!("{:#?}", contrack);
                //
                //
                //     }
                //     guard.clear_ready();
                //
                // }


                _ = rx.changed() => {
                        if *rx.borrow() {
                            break;
                        }
                    }
                // _ = interval_1.tick() => {
                //     let con = del_rev.try_recv();
                //     if con.is_ok() {
                //         let data = con.unwrap();
                //         let cons_ = connections.get(&data, 0);
                //         if cons_.is_ok(){
                //             let cons_ = cons_.unwrap();
                //             // Check if connections still exits
                //             let src_ip = Ipv4Addr::from(cons_.remote_ip);
                //             let port = cons_.remote_port;
                //             let protocal = if cons_.protocal == 6 {"TCP"} else {"UDP"};
                //             if connections.remove(&data).is_ok() {
                //                 info!("Closing {} on {}:{}", protocal, src_ip.to_string(), &port);
                //             } else {
                //             // The connections maybe removed by `rst` signal
                //                 info!(
                //                     "Closed {}:{} on {}",
                //                     src_ip.to_string(),
                //                     port,
                //                     protocal
                //                 );
                //             }
                //         }
                //
                //     }
                // }
                _ = interval_2.tick() => {
                    let new_config: AppConfig
                        = Figment::new().merge(Toml::file(&opt.config)).extract()?;
                    if new_config.len() != config_len {
                        _ = load_config(&mut bpf, &new_config);
                        config_len = new_config.len();
                    };
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
    let mut bpf = t.await.unwrap().expect("bpf returned");
    let program: &mut Xdp = bpf.program_mut("sfw").unwrap().try_into()?;
    if program.detach(xdp_link).is_ok() {
        info!("detached xdp program");
    }
    let program: &mut SchedClassifier =
        bpf.program_mut("sfw_egress").unwrap().try_into()?;
    if program.detach(tc_link).is_ok() {
        info!("detached xdp program");
    }
    info!("Exiting...");
    Ok(())
}

fn load_config(bpf: &mut Bpf, config: &AppConfig) -> Result<(), anyhow::Error> {
    if let Some(dns) = &config.dns {
        let mut dns_list: HashMap<_, u32, u8> =
            HashMap::try_from(bpf.map_mut("DNS_ADDR").unwrap())?;
        for k in dns {
            let ip_addrs: Ipv4Addr = k.parse().unwrap();
            let addrs: u32 = ip_addrs.to_bits();
            info!("allowed DNS IP: {:}", ip_addrs.to_string());
            _ = dns_list.insert(addrs, 0x1, 0);
        }
    }
    if let Some(tcp) = &config.tcp_in {
        if let Some(n) = &tcp.sport {
            let mut tcp_in_port: Array<_, u8> =
                Array::try_from(bpf.map_mut("TCP_IN_SPORT").unwrap())?;
            for port in 0..65536 {
                tcp_in_port.set(port, 0x0, 0)?;
            }
            for port in n {
                info!("Allow incomming from tcp port: {:?}", port);
                tcp_in_port.set(u32::from(*port), 1u8, 0)?;
            }
        }
        if let Some(n) = &tcp.dport {
            let mut tcp_in_port: Array<_, u8> =
                Array::try_from(bpf.map_mut("TCP_IN_DPORT").unwrap())?;
            for port in 0..65536 {
                tcp_in_port.set(port, 0x0, 0)?;
            }
            for port in n {
                info!("Allow incomming to tcp port: {:?}", port);
                tcp_in_port.set(u32::from(*port), 1u8, 0)?;
            }
        }
    }
    if let Some(tcp) = &config.tcp_out {
        if let Some(n) = &tcp.sport {
            let mut tcp_out_port: Array<_, u8> =
                Array::try_from(bpf.map_mut("TCP_OUT_SPORT").unwrap())?;
            for port in 0..65536 {
                tcp_out_port.set(port, 0x0, 0)?;
            }
            for port in n {
                info!("Allow outgoing from tcp port: {:?}", port);
                tcp_out_port.set(u32::from(*port), 1u8, 0)?;
            }
        }
        if let Some(n) = &tcp.dport {
            let mut tcp_out_port: Array<_, u8> =
                Array::try_from(bpf.map_mut("TCP_OUT_DPORT").unwrap())?;
            for port in 0..65536 {
                tcp_out_port.set(port, 0x0, 0)?;
            }
            for port in n {
                info!("Allow outgoing to tcp port: {:?}", port);
                tcp_out_port.set(u32::from(*port), 1u8, 0)?;
            }
        }
    }
    if let Some(udp) = &config.udp_in {
        if let Some(n) = &udp.sport {
            let mut udp_in_port: Array<_, u8> =
                Array::try_from(bpf.map_mut("UDP_IN_SPORT").unwrap())?;
            for port in 0..65536 {
                udp_in_port.set(port, 0x0, 0)?;
            }
            for port in n {
                info!("Allow incomming from udp port {:?}", port);
                udp_in_port.set(u32::from(*port), 1u8, 0)?;
            }
        }
        if let Some(n) = &udp.dport {
            let mut udp_in_port: Array<_, u8> =
                Array::try_from(bpf.map_mut("UDP_IN_DPORT").unwrap())?;
            for port in 0..65536 {
                udp_in_port.set(port, 0x0, 0)?;
            }
            for port in n {
                info!("Allow incomming to udp port {:?}", port);
                udp_in_port.set(u32::from(*port), 1u8, 0)?;
            }
        }
    }
    if let Some(udp) = &config.udp_out {
        if let Some(n) = &udp.sport {
            let mut udp_out_port: Array<_, u8> =
                Array::try_from(bpf.map_mut("UDP_OUT_SPORT").unwrap())?;
            for port in 0..65536 {
                udp_out_port.set(port, 0x0, 0)?;
            }
            for port in n {
                info!("Allow outgoing from udp port {:?}", port);
                udp_out_port.set(u32::from(*port), 1u8, 0)?;
            }
        }
        if let Some(n) = &udp.dport {
            let mut udp_out_port: Array<_, u8> =
                Array::try_from(bpf.map_mut("UDP_OUT_DPORT").unwrap())?;
            for port in 0..65536 {
                udp_out_port.set(port, 0x0, 0)?;
            }
            for port in n {
                info!("Allow outgoing to udp port {:?}", port);
                udp_out_port.set(u32::from(*port), 1u8, 0)?;
            }
        }
    }
    info!("Done parsing config!");
    Ok(())
}
