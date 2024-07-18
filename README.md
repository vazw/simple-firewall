# simple-firewall a simple kernel level firewall

## Simeple - Low Memory-Footprint and Reliable using XDP

![ScreenShot](https://github.com/vazw/simple-firewall/blob/main/screenshot/screenshot.png)

## Prerequisites

1. Install bpf-linker: `cargo install bpf-linker`

## Features

1. Blazingly fast
2. Filter TCP and UDP with specified PORT
3. Specified DNS reslover
4. TCP state recognizer
5. Aggressive TCP reset on first syn

#### HOW Aggressive TCP reset work?

```
[Client]            [Firewall]          [Server]
    |                   |                   |
    | -----> syn -----> | if NEW connection |
    |                   | Firewall will act |
    | <--- syn ack ---- | like it's serving |
    |                   | our service       |
    | ------- ack ----> |                   |
    |                   |it's actually dummy|
    | <----- rst <----- | respone by XDP_TX |
    |                   |                   |
    | ------ syn -------------------------> |
    |                   |                   |
    | <--- syn ack ------------------------ |
    |                   |                   |
    | ------- ack ------------------------> |
    |                   |                   |
    | <-------- ESTABLISHED --------------> |

```

```bash
cargo sfw build-ebpf
```

## Build Userspace

```bash
cargo build
```

## Build eBPF and Userspace

```bash
cargo sfw build
```

## Run

```bash
RUST_LOG=info cargo sfw run -i <NIC> -c <path-to-config.toml>
```

To perform a release build you can use the `--release` flag.
You may also change the target architecture with the `--target` flag.

## Config

simple-firewall use simple toml config pattern

### config options

- `tcp_in` Incomming-Port a port from outside comming to us.(etc. web-browsing)
- `tcp_out` Outgoing-Port a port from our server to outside.(etc. serving website/service)
- `udp_in` Incomming-Port a port from outside comming to us.(etc. web-browsing)
- `udp_out` Outgoing-Port a port from our server to outside.(etc. serving website/service)

`sfwconfig.toml`

```
dns = ["208.67.222.222", "9.9.9.9"]

[tcp_in]
sport = []
dport = [4869,8000,8008]

[tcp_out]
sport = [22000,4869,8000, 8008]
dport = [22,80,443,8181,10022, 20086]

[udp_in]
sport = [22000,21027]
dport = [22000,21027]

[udp_out]
sport = [22000,21027]
dport = [22000,21027, 123, 67, 8443]

# 123 = NTP network time
# 67 = router
# 22 = ssh
# 80,443 = regular http
# 22000 and 21027 = syncthing
```

## Installation

```bash
git clone https://github.com/vazw/simple-firewall.git && cd simple-firewall
cargo install bpf-linker
cargo sfw install --path <install-path> # Default is /usr/bin/
```

then make a auto-startup script for it with `sfw -i <NIC> -c <path-to-config.toml>`

in my case I was using `pkexec` to auto-startup with my SwayWM started

`.config/sway/config`

```bash
exec pkexec sfw -i wlp1s0 -c /etc/sfw/sfwconfig.toml &
```
