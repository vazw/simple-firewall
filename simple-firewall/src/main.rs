use std::net::Ipv4Addr;

use aya::util::nr_cpus;

use anyhow::Context;
use aya::maps::{Array, HashMap, PerCpuArray, PerCpuValues};
use aya::programs::{Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use clap::Parser;
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use log::{debug, info, warn};
use tokio::signal;
use tokio::time::{interval, Duration};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp1s0")]
    iface: String,
    #[clap(short, long, default_value = "./fwcfg.yaml")]
    config: String,
}

fn load_config(bpf: &mut Bpf, opt: &Opt) -> Result<(), anyhow::Error> {
    let config: std::collections::HashMap<String, String> =
        Figment::new().merge(Yaml::file(&opt.config)).extract()?;
    let mut rate_limit: Array<_, u32> = Array::try_from(bpf.map_mut("RATE_LIMIT").unwrap())?;
    rate_limit.set(0, 1000, 0)?;
    for (k, v) in config.iter() {
        if v.contains("tcp") {
            if v.contains('i') {
                let mut tcp_port: HashMap<_, u16, u16> =
                    HashMap::try_from(bpf.map_mut("IAP").unwrap())?;
                let port: u16 = k.parse().unwrap();
                info!("incomming tcp port: {:?}", port);
                tcp_port.insert(port, port, 0)?;
            }
            if v.contains('o') {
                let mut tcp_port: HashMap<_, u16, u16> =
                    HashMap::try_from(bpf.map_mut("OAP").unwrap())?;
                let port: u16 = k.parse().unwrap();
                info!("outgoing tcp port: {:?}", port);
                tcp_port.insert(port, port, 0)?;
            }
        }
        if v.contains("udp") {
            if v.contains('i') {
                let mut udp_port: HashMap<_, u16, u16> =
                    HashMap::try_from(bpf.map_mut("UDPIAP").unwrap())?;
                let port: u16 = k.parse().unwrap();
                info!("incomming udp port {:?}", port);
                udp_port.insert(port, port, 0)?;
            }
            if v.contains('o') {
                let mut udp_port: HashMap<_, u16, u16> =
                    HashMap::try_from(bpf.map_mut("UDPOAP").unwrap())?;
                let port: u16 = k.parse().unwrap();
                info!("outgoing udp port {:?}", port);
                udp_port.insert(port, port, 0)?;
            }
        }
        if v.contains("dns") {
            let mut dns_list: HashMap<_, u32, u32> =
                HashMap::try_from(bpf.map_mut("ALLST").unwrap())?;
            let ip_addrs: Ipv4Addr = k.parse().unwrap();
            let addrs: u32 = ip_addrs.into();
            info!("allowed DNS IP: {:}", ip_addrs.to_string());
            dns_list.insert(addrs, addrs, 0)?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    let opt = Opt::parse();
    env_logger::init();

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
        "../../target/bpfel-unknown-none/debug/simple-firewall"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/simple-firewall"
    ))?;
    if let Err(e) = BpfLogger::init(&mut bpf) {
        // This can happen if you remove all log statements from your eBPF program.
        warn!("failed to initialize eBPF logger: {}", e);
    }
    let program: &mut Xdp = bpf.program_mut("simple_firewall").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;

    let _ = load_config(&mut bpf, &opt);
    let mut interval1 = interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Exiting...");
                break;
            }
            _ = interval1.tick() => {
                let mut rate_limit: PerCpuArray<_, u32>= PerCpuArray::try_from(bpf.map_mut("RATE").unwrap())?;
                rate_limit.set(0,PerCpuValues::try_from(vec![0u32;nr_cpus()?])?,0)?;
            }
        }
    }
    Ok(())
}
