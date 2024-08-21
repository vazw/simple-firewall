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
    use std::io::{stdin, stdout, Write};
    let mut s = String::new();
    print!("Do you want to copy config file? [y]es/[n]o: ");
    let _ = stdout().flush();
    stdin()
        .read_line(&mut s)
        .expect("Did not enter a correct string");
    if let Some('\n') = s.chars().next_back() {
        s.pop();
    }
    if let Some('\r') = s.chars().next_back() {
        s.pop();
    }
    if s.to_lowercase().eq("y") {
        let mut args: Vec<_> =
            "sudo mkdir".trim().split_terminator(' ').collect();
        args.push("-p");
        args.push("/etc/sfw/");

        // run the command
        _ = Command::new(args.first().expect("No first argument"))
            .args(args.iter().skip(1))
            .status()
            .expect("failed to run the command");

        let mut args: Vec<_> = "sudo cp".trim().split_terminator(' ').collect();
        args.push("./sfwconfig.toml");
        args.push("/etc/sfw/sfwconfig.toml");
        let status = Command::new(args.first().expect("No first argument"))
            .args(args.iter().skip(1))
            .status()
            .expect("failed to run the command");

        if !status.success() {
            anyhow::bail!("Failed to copy config file `{}`", args.join(" "));
        }
        println!("Installed config on `/etc/sfw/sfwconfig.toml`");
    }
    println!(
        r"
then make a auto-startup script for it with `sfw -i <NIC> -c <path-to-config.toml>`

in my case I was using `pkexec` to auto-startup with my SwayWM started

`.config/sway/config`

```bash
exec pkexec sfw -i wlp1s0 -c /etc/sfw/sfwconfig.toml &
```
    "
    );
    Ok(())
}
