# simple-firewall

## Simeple - Low Memory-Footprint and Reliable.

![ScreenShot](https://github.com/vazw/simple-firewall/blob/main/screenshot/screenshot.png)

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Build eBPF

```bash
cargo xtask build-ebpf
```

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo xtask build
```

## Run

```bash
RUST_LOG=info cargo xtask run -i <NIC> -c <path-to-config.yaml>
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Config

simple-firewall use simple yaml config pattern

### config options

- `i` Imcomming-Port a port from outside server comming to us.(etc. web-browsing)
- `o` Outgoing-Port a port from our server to outside.(etc. serving website/service)
- `tcp` Allowed on TCP protocal
- `udp` Allowed on UDP protocal

these options can be nested likes example below except `dns` which we will provide only allowed DNS reslover.

`fwcfg.yaml`

```
{
  "80": "i,tcp",
  "8181": "i,tcp",
  "443": "i,tcp",
  "123": "i,udp", # sync time
  "67": "i,udp", # router
  # "5353": "o,udp", # dns multi-cast
  "22000": "i,o,tcp,udp", #syncthing
  "21027": "i,o,udp", #// syncthing
  "22022": "i,o,tcp", #// custom ssh
  "4869": "i,o,tcp", #// nostr relay
  "208.67.222.222": "dns", #// DNS
  "9.9.9.9": "dns", #// DNS
}
```
