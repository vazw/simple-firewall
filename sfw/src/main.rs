mod build;
mod build_ebpf;
mod install;
mod run;

use std::fs::File;
use std::io::Write;

use std::process::exit;

use anyhow::Ok;
use aya::util::nr_cpus;
use clap::Parser;

#[derive(Debug, Parser)]
pub struct Options {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Debug, Parser)]
enum Command {
    BuildEbpf(build_ebpf::Options),
    Build(build::Options),
    Run(run::Options),
    Install(install::Options),
}

fn setup() -> Result<(), anyhow::Error> {
    let cpus = nr_cpus()?;
    let mut f = File::create("./simple-firewall-ebpf/src/cpus.rs")?;
    let context = format!("pub const CPUS: u32 = {cpus};");
    f.write_all(context.as_bytes())?;
    Ok(())
}

fn main() {
    let opts = Options::parse();
    if let Err(e) = setup() {
        eprintln!("{e:#}");
    }

    use Command::*;
    let ret = match opts.command {
        BuildEbpf(opts) => build_ebpf::build_ebpf(opts),
        Run(opts) => run::run(opts),
        Build(opts) => build::build(opts),
        Install(opts) => install::run(opts),
    };

    if let Err(e) = ret {
        eprintln!("{e:#}");
        exit(1);
    }
}
