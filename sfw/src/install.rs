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
    let bin_path = "target/release/simple-firewall";
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
    Ok(())
}
