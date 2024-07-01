use std::process::Command;

use anyhow::Context as _;
use clap::Parser;

use crate::{
    build::{build, Options as BuildOptions},
    build_ebpf::Architecture,
};

#[derive(Debug, Parser)]
pub struct Options {
    /// Set the endianness of the BPF target
    #[clap(default_value = "bpfel-unknown-none", long)]
    pub bpf_target: Architecture,
    /// Build and run the release target
    // #[clap(long)]
    // pub release: bool,
    /// The command used to wrap your application
    // #[clap(short, long, default_value = "sudo cp")]
    // pub runner: String,
    /// Arguments to pass to your application
    #[clap(short, long, default_value = "/usr/bin/", name = "install path")]
    pub path: String,
}

/// Build and run the project
pub fn run(opts: Options) -> Result<(), anyhow::Error> {
    // Build our ebpf program and the project
    build(BuildOptions {
        bpf_target: opts.bpf_target,
        release: true,
    })
    .context("Error while building project")?;

    // profile we are building (release or debug)
    let bin_path = "target/release/sfw";
    let install_path = if opts.path.ends_with('/') {
        format!("{}sfw", opts.path)
    } else {
        format!("{}/sfw", opts.path)
    };

    // configure args
    let mut args: Vec<_> = "sudo cp".trim().split_terminator(' ').collect();
    args.push(bin_path);
    args.push(&install_path);

    // run the command
    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .expect("failed to run the command");

    if !status.success() {
        anyhow::bail!("Failed to run `{}`", args.join(" "));
    }
    println!("Installed simple-firewall on `{}`", install_path);
    // copy config
    let mut args: Vec<_> = "sudo cp".trim().split_terminator(' ').collect();
    args.push("fwcfg.yaml");
    args.push("/etc/fwcfg.yaml");

    // run the command
    let status = Command::new(args.first().expect("No first argument"))
        .args(args.iter().skip(1))
        .status()
        .expect("failed to run the command");

    if !status.success() {
        anyhow::bail!("Failed to copy config file `{}`", args.join(" "));
    }
    println!("Installed config on `/etc/fwcfg.yaml`");
    println!(
        r"
then make a auto-startup script for it with `sfw -i <NIC> -c <path-to-config.yaml>`

in my case I was using `pkexec` to auto-startup with my SwayWM started

`.config/sway/config`

```bash
exec pkexec sfw -i wlp1s0 -c /etc/fwcfg.yaml &
```
    "
    );
    Ok(())
}
