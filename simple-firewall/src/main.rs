#![allow(unreachable_code)]
use std::net::Ipv4Addr;
use std::str::FromStr;

use aya::util::{nr_cpus, online_cpus};

use anyhow::{Context, Ok};
use aya::maps::{Array, AsyncPerfEventArray, HashMap, IterableMap, PerCpuArray, PerCpuValues};
use aya::programs::{KProbe, Xdp, XdpFlags};
use aya::{include_bytes_aligned, Bpf};
use aya_log::BpfLogger;
use bytes::BytesMut;
use clap::Parser;
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use local_ip_address::local_ip;
use log::{debug, info, warn};
use simple_firewall_common::{Connection, Session};
use tokio::signal;
use tokio::time::{interval, Duration, Instant};

#[derive(Debug, Parser)]
struct Opt {
    #[clap(short, long, default_value = "wlp1s0")]
    iface: String,
    #[clap(short, long, default_value = "./fwcfg.yaml")]
    config: String,
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
    let program: &mut KProbe = bpf.program_mut("kprobetcp").unwrap().try_into()?;
    program.load()?;
    program.attach("tcp_connect", 0)?;

    let mut config_len: usize;
    let config = Figment::new().merge(Yaml::file(&opt.config));
    let config_: std::collections::HashMap<String, String> = config.extract()?;
    let host_ip = local_ip().expect("attach to network?");
    let host_addr = Ipv4Addr::from_str(&host_ip.to_string()).expect("ip addrs");

    config_len = config_.len();
    _ = load_config(&mut bpf, &opt, &config_, &host_addr);
    let mut perf_array = AsyncPerfEventArray::try_from(bpf.take_map("NEW").unwrap())?;
    let (add_send, mut add_rev) = tokio::sync::mpsc::channel(1024);
    let (del_send, mut del_rev) = tokio::sync::mpsc::channel(1024);

    for cpu_id in online_cpus()? {
        let del_send = del_send.clone();
        let add_send = add_send.clone();
        let mut perf_buf = perf_array.open(cpu_id, None)?;
        tokio::task::spawn(async move {
            let mut u_connection: std::collections::HashMap<Connection, Instant> =
                std::collections::HashMap::new();
            let mut buf = vec![BytesMut::with_capacity(1024); 10];
            loop {
                let events = perf_buf.read_events(&mut buf).await?;
                for event in buf.iter_mut().take(events.read) {
                    let key = unsafe { &*(event.as_ptr() as *const Connection) };
                    let src_ip: Ipv4Addr = key.src_ip.into();
                    let dst_ip: Ipv4Addr = key.dst_ip.into();
                    let protocal = if key.protocol == 6 { "TCP" } else { "UDP" };

                    if let Some(timer) = u_connection.get(key) {
                        if timer.elapsed().as_secs() == 120 {
                            // _ = connections.remove(&key);
                            _ = u_connection.remove(key);
                            let sess = Session {
                                src_ip: key.src_ip,
                                src_port: key.src_port,
                                protocol: 6,
                            };
                            del_send.send(sess).await?;
                            if dst_ip == host_addr {
                                debug!(
                                    "{} HOST:{} !<-- {}::{}",
                                    protocal,
                                    key.dst_port,
                                    src_ip.to_string(),
                                    key.src_port
                                );
                            } else if src_ip == host_addr {
                                debug!(
                                    "{} HOST::{} -->! {}:{}",
                                    protocal,
                                    key.src_port,
                                    dst_ip.to_string(),
                                    key.dst_port
                                );
                            } else {
                                debug!(
                                    "{} {}:{} -->! {}:{}",
                                    protocal,
                                    src_ip.to_string(),
                                    key.src_port,
                                    dst_ip.to_string(),
                                    key.dst_port
                                );
                            }
                        };
                    } else {
                        if dst_ip == host_addr {
                            debug!(
                                "GOT {} HOST::{} <-- {}:{}",
                                protocal, key.dst_port, src_ip, key.src_port
                            );
                        } else if src_ip == host_addr {
                            let sess = Session {
                                src_ip: key.dst_ip,
                                src_port: key.dst_port,
                                protocol: 6,
                            };
                            // _ = connections.insert(con, con, 0);
                            add_send.send((sess, *key)).await?;
                            info!(
                                "Bind {} HOST::{} --> {}:{}",
                                protocal, key.src_port, dst_ip, key.dst_port
                            );
                        } else {
                            debug!(
                                "{} {}:{} --> {}:{}",
                                protocal,
                                src_ip.to_string(),
                                key.src_port,
                                dst_ip.to_string(),
                                key.dst_port
                            );
                        }
                        u_connection.insert(*key, Instant::now());
                    };
                }
            }

            Ok::<_>(())
        });
    }
    _ = tokio::task::spawn(async move {
        let mut interval_1 = interval(Duration::from_millis(10));
        let mut heart_rate = interval(Duration::from_secs(1));
        let mut heart_reset: bool = false;
        loop {
            tokio::select! {
                _ = interval_1.tick() => {
                    let new_config: std::collections::HashMap<String, String> = Figment::new().merge(Yaml::file(&opt.config)).extract()?;
                    if new_config.len() != config_len {
                        _ = load_config(&mut bpf, &opt, &new_config, &host_addr);
                        config_len = new_config.len();
                    };

                    if heart_reset {
                        let mut rate_limit: PerCpuArray<_, u32>= PerCpuArray::try_from(bpf.map_mut("RATE").unwrap())?;
                        // let rate = rate_limit.get(&0u32,0);
                        // println!("1s {:?}", rate.unwrap().iter().sum::<u32>());
                        rate_limit.set(0,PerCpuValues::try_from(vec![0u32;nr_cpus()?])?,0)?;
                        heart_reset = false;
                    }

                    let mut connections: HashMap<_, Session, Connection> = HashMap::try_from(bpf.map_mut("CONS").unwrap())?;
                    let con = add_rev.try_recv();
                    if con.is_ok() {
                        let (sess, con) = con.unwrap();
                        let src_ip = Ipv4Addr::from(con.src_ip);
                        let dst_ip = Ipv4Addr::from(sess.src_ip);
                        let protocal = if con.protocol == 6 {"TCP"} else {"UDP"};
                        debug!("Binding {} {}:{} -> {}:{}", protocal, src_ip, con.src_port, dst_ip, sess.src_port);
                        connections.insert(sess,con,0)?;
                    }

                    let con = del_rev.try_recv();
                    if con.is_ok() {
                        let con = con.unwrap();
                        let src_ip = Ipv4Addr::from(con.src_ip);
                        let protocal = if con.protocol == 6 {"TCP"} else {"UDP"};
                        debug!("Removing {}:{} -> {}", src_ip, con.src_port, protocal);
                        connections.remove(&con)?;
                    }

                    // let cons = connections.keys();
                    // for con in cons {
                    //     let con = if con.is_err() {
                    //         break;
                    //     } else {con.unwrap()};
                    //     let src_ip = Ipv4Addr::from(con.src_ip);
                    //     let protocal = if con.protocol == 6 {"TCP"} else {"UDP"};
                    //     println!("Sessions {}:{} -> {}", src_ip, con.src_port, protocal);
                    // }

                }
                _ = heart_rate.tick() => {
                        heart_reset=true;
                    }
            }
        }
        Ok(())
    });
    // loop {
    //     tokio::select! {
    //         _ = signal::ctrl_c() => {
    //             info!("Exiting...");
    //             break;
    //         }
    //     }
    // }
    signal::ctrl_c().await?;
    info!("Exiting...");
    Ok(())
}

fn load_config(
    bpf: &mut Bpf,
    opt: &Opt,
    config: &std::collections::HashMap<String, String>,
    host_addr: &Ipv4Addr,
) -> Result<(), anyhow::Error> {
    println!("Listening on {} IP: {}", &opt.iface, &host_addr.to_string());
    // Clear mem first
    //
    let program: &mut Xdp = bpf.program_mut("sfw").unwrap().try_into()?;
    program.unload().unwrap_or(());
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())
        .context("failed to attach the XDP program with default flags - try changing XdpFlags::default() to XdpFlags::SKB_MODE")?;
    let mut rate_limit: Array<_, u32> = Array::try_from(bpf.map_mut("RATE_LIMIT").unwrap())?;
    rate_limit.set(0, 1000 * nr_cpus()? as u32, 0)?;
    let mut host: Array<_, u32> = Array::try_from(bpf.map_mut("HOST").unwrap())?;
    host.set(0, u32::from(*host_addr), 0)?;
    for (k, v) in config.iter() {
        if v.contains("tcp") {
            if v.contains('i') {
                let mut tcp_in_port: HashMap<_, u16, u16> =
                    HashMap::try_from(bpf.map_mut("IAP").unwrap())?;
                let port: u16 = k.parse().unwrap();
                info!("incomming tcp port: {:?}", port);
                tcp_in_port.insert(port, port, 0)?;
            }
            if v.contains('o') {
                let mut tcp_out_port: HashMap<_, u16, u16> =
                    HashMap::try_from(bpf.map_mut("OAP").unwrap())?;
                let port: u16 = k.parse().unwrap();
                info!("outgoing tcp port: {:?}", port);
                tcp_out_port.insert(port, port, 0)?;
            }
        }
        if v.contains("udp") {
            if v.contains('i') {
                let mut udp_in_port: HashMap<_, u16, u16> =
                    HashMap::try_from(bpf.map_mut("UDPIAP").unwrap())?;
                let port: u16 = k.parse().unwrap();
                info!("incomming udp port {:?}", port);
                udp_in_port.insert(port, port, 0)?;
            }
            if v.contains('o') {
                let mut udp_out_port: HashMap<_, u16, u16> =
                    HashMap::try_from(bpf.map_mut("UDPOAP").unwrap())?;
                let port: u16 = k.parse().unwrap();
                info!("outgoing udp port {:?}", port);
                udp_out_port.insert(port, port, 0)?;
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
