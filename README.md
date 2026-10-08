# chkbounce

**chkbounce** is a network diagnostic tool that determines which types of traffic can traverse the path between two hosts.  It operates in a client/server model: a persistent server process listens for incoming client connections, negotiates a set of probes, and reports back in real time which packets it received.  Supported probe types are **ICMP/ICMPv6** (all 256 type numbers or a specific subset), **TCP** (by port number), and **UDP** (by port number), over **IPv4 or IPv6**.

---

## Features

- Tests ICMP reachability across all 256 type numbers, or any subset/range
- Tests TCP port reachability by attempting connections
- Tests UDP reachability by sending datagrams
- Flexible range syntax for specifying what to probe (`22,25-30,80,443`)
- Per-probe configurable timeout
- Tests either direction of the path (client→server, server→client) or both, flagging asymmetric results
- Server runs persistently and handles multiple client sessions sequentially
- IPv4 and IPv6; the client accepts hostnames and numeric addresses, and `-4`/`-6` force a family
- CSV and JSON export for analysis, with timestamps and tool version on every record
- Lock-step protocol: the server opens exactly one socket at a time, just before each probe is sent, so there is no limit on the number of probes in a session

---

## Requirements

- Linux (uses raw sockets via the kernel's `SOCK_RAW` interface)
- **Root privileges** or `CAP_NET_RAW` on both the client and server (required for ICMP raw sockets)
- `gcc` and GNU `make` to build from source

---

## Building from Source

```sh
git clone https://github.com/josephcolton/chkbounce.git
cd chkbounce
make
```

The resulting binary is `./chkbounce`.

---

## Installation

```sh
sudo make install
```

This installs:

| File | Destination |
|------|-------------|
| `chkbounce` | `/usr/sbin/chkbounce` |
| `chkbounce.8` | `/usr/share/man/man8/chkbounce.8.gz` |

To remove the installed files:

```sh
sudo make uninstall
```

To install to a different prefix (e.g., `/usr/local`):

```sh
sudo make install PREFIX=/usr/local
```

---

## Usage

### Server Mode

Start the server on the machine whose network reachability you want to test.  The server binds to the control port and waits for clients indefinitely; press **Ctrl-C** to stop it.

```
chkbounce -s [OPTIONS]
```

### Client Mode

Run the client on the machine that will generate the probe traffic.  The client connects to the server, negotiates which probes to run, sends each probe, and prints a final report.

```
chkbounce -c SERVER [OPTIONS]
```

`SERVER` may be a hostname (resolved via DNS) or a numeric IPv4 or IPv6 address.  Without `-4`/`-6`, the first address the resolver returns is used.  The session (control connection and all probes) uses that one address family.

---

## Options

| Option | Description |
|--------|-------------|
| `-s`, `--server` | Run in server mode |
| `-c`, `--client` | Run in client mode |
| `-4`, `--ipv4` | Client: use IPv4.  Server: accept IPv4 clients only. |
| `-6`, `--ipv6` | Client: use IPv6.  Server: accept IPv6 clients only.  (By default the server accepts both.) |
| `-p NUM`, `--port=NUM` | TCP port used for the control channel (default: **1234**) |
| `--timeout=NUM` | Per-probe timeout in seconds (default: **2**) |
| `-i[TYPES]`, `--icmp[=TYPES]` | Enable ICMP probes.  `TYPES` is a range list of ICMP type numbers (0–255).  Omit `TYPES` to probe all 256 types. |
| `-t[PORTS]`, `--tcp[=PORTS]` | Enable TCP probes.  `PORTS` is a range list of port numbers.  Omit `PORTS` to use the default port list. |
| `-u[PORTS]`, `--udp[=PORTS]` | Enable UDP probes.  `PORTS` is a range list of port numbers.  Omit `PORTS` to use the default port list. |
| `-r`, `--reverse` | Reverse direction: the server sends each probe to the client, and the client reports what arrived |
| `-b`, `--both` | Run each probe in both directions (forward, then immediately reverse) and mark results that differ as `ASYMMETRIC` |
| `-o FILE`, `--output=FILE` | Write the final report to `FILE` in addition to printing it to stdout.  The file is created or overwritten.  Progress and connection messages are not written to the file. |
| `--csv=FILE` | Append results to `FILE` as CSV, one row per probe and direction.  A header row is written if the file is new or empty, so many runs can be collected in one file. |
| `--json=FILE` | Write the run (metadata, per-probe results, summary) to `FILE` as one JSON document.  The file is overwritten. |
| `-V`, `--version` | Print the version (the git commit it was built from) and exit. |

**Default port lists** (used when the flag is given without an explicit list):

| Protocol | Default ports |
|----------|--------------|
| TCP | 22, 80, 443, 8080, 8443 |
| UDP | 53, 123, 161 |

If **none** of `-i`, `-t`, or `-u` is specified, all three protocols are probed using their defaults (equivalent to `-i -t -u`).

**Short-option note:** Because `-i`, `-t`, and `-u` take optional arguments, there must be **no space** between the flag and its value when using short options:

```sh
-t80,443      # correct  (short form)
--tcp=80,443  # correct  (long form)
-t 80,443     # WRONG — interpreted as -t (default ports) followed by argument 80,443
```

---

## Range Syntax

Port numbers and ICMP type numbers are specified as a comma-separated list of individual values and/or inclusive ranges:

```
VALUE[,VALUE|RANGE...]

where RANGE = START-END
```

### Examples

| Expression | Expands to |
|------------|-----------|
| `80` | 80 |
| `22,80,443` | 22, 80, 443 |
| `8080-8090` | 8080, 8081, …, 8090 |
| `22,25-30,80,443` | 22, 25, 26, 27, 28, 29, 30, 80, 443 |
| `0,3,8-11,255` | 0, 3, 8, 9, 10, 11, 255 |

Valid ranges:
- ICMP type numbers: **0–255**
- TCP/UDP port numbers: **1–65535**

---

## Examples

### Start a persistent server on the default control port

```sh
sudo chkbounce -s
```

### Start a server on a non-standard control port with a 5-second timeout

```sh
sudo chkbounce -s -p 5000 --timeout=5
```

### Run the client against a server by hostname, probing all three protocols

```sh
sudo chkbounce -c server.example.com
```

### Probe only ICMP (all 256 types) against a server by IP

```sh
sudo chkbounce -c 192.168.1.50 -i
```

### Probe specific ICMP types (echo reply, destination unreachable, echo request, time exceeded)

```sh
sudo chkbounce -c 192.168.1.50 -i0,3,8,11
```

### Probe TCP on specific ports

```sh
sudo chkbounce -c 192.168.1.50 -t22,80,443,8080-8090
```

### Probe UDP on a range of ports

```sh
sudo chkbounce -c 192.168.1.50 -u53,67-69,123,161
```

### Compare both directions of a path

```sh
sudo chkbounce -c 192.168.1.50 -b -i -t22,80,443
```

### Probe all ICMPv6 types over IPv6, both directions, saving CSV and JSON

```sh
sudo chkbounce -6 -c server.example.com -i -b --csv=results.csv --json=run.json
```

In an IPv6 session, `-i` type numbers are ICMPv6 types (e.g. 128 = Echo Request, 160 = Extended Echo Request).

### Save the report to a file

```sh
sudo chkbounce -c 192.168.1.50 -t22,80,443 --output=report.txt
```

### Combine protocols with a custom control port, timeout, and output file

```sh
sudo chkbounce -c firewall.internal -p 5000 --timeout=3 -i0,3,8 -t22,80,443 -u53,123 --output=/tmp/fw-report.txt
```

### Client and server on the same machine (loopback test)

```sh
# Terminal 1
sudo chkbounce -s

# Terminal 2
sudo chkbounce -c 127.0.0.1 -t80,443 -u53
```

---

## How It Works

### Overview

chkbounce uses a TCP control channel (default port 1234) to coordinate the probe sequence between client and server.  All probe results are reported back to the client over this same channel.

### Protocol

1. **Connect** — The client opens a TCP connection to the server's control port.
2. **Negotiate** — The client sends the complete list of probes it intends to run (protocol and port/type number for each).  The server acknowledges with a *ready* signal.
3. **Probe loop** — For each probe, the client and server execute a four-step handshake:
   1. Client → Server: *"Open this port/type."*
   2. Server → Client: *"Socket is open and listening."*  (The server opens exactly one socket here, immediately before the probe is fired.)
   3. Client sends the probe packet (ICMP, TCP connect, or UDP datagram) to the server.
   4. Server → Client: *"Received"* (immediately on receipt) or *"Not received"* (after the per-probe timeout expires).
4. **Reverse probes** (`-r` / `-b`) — the roles swap for that probe:
   1. Client opens its own listening socket, then sends *"Send me this port/type."*
   2. Server sends the probe packet to the client's address (as seen on the control connection).
   3. Server → Client: *"Sent."*  The client waits up to its own timeout and records the result itself.

   With `-b`, each probe runs forward and then immediately in reverse, so the two results are close in time.
5. **Done** — After the last probe the client sends a *done* message, the server closes the client session, and the server loops back to accept the next incoming client.

### Per-probe socket lifecycle

Opening one socket per probe (rather than all sockets up front during negotiation) avoids hitting per-process file-descriptor limits even when testing thousands of ports.  The ICMP raw socket is an exception: it is opened once at the start of a client session and reused for all ICMP probes, then closed when the session ends.

### ICMP filtering

The receiver uses a single raw socket per session (`IPPROTO_ICMP` for IPv4, `IPPROTO_ICMPV6` for IPv6) and filters incoming packets by the peer's address (taken from the control-channel TCP connection), the expected type number, and a sequence-number tag.  Every ICMP probe carries the identifier `0xCB0C` and a sequence number of `(type << 1) | direction`.  The tag stops the kernel's automatic reply to an earlier probe from being mistaken for a later one; for example, the Echo Reply (ICMPv6 129) the kernel sends back for a type 128 probe.  Only the sequence number is checked, because NATs rewrite the echo identifier.  Unrelated ICMP traffic arriving during a probe window is discarded.

Probes are sent from the local address of the control connection, so the source-address filter matches even on hosts with several addresses (common with IPv6).

### Probe methods

| Protocol | Client action | Server action |
|----------|--------------|---------------|
| ICMP | Sends a raw ICMP packet with the requested type number | Receives on a raw ICMP socket; filters by source IP and type |
| TCP | Non-blocking `connect()` to the server's port | `accept()` on a listening socket |
| UDP | Sends a small datagram to the server's port | `recvfrom()` on a bound socket; filters by source IP |

---

## Machine-Readable Output

`--csv` writes one row per probe and direction:

```
run_start,version,family,server_host,server_addr,client_addr,timeout_sec,proto,number,direction,received,probe_time
2026-10-08T14:44:51.841Z,2d1e46d,IPv4,127.0.0.1,127.0.0.1,127.0.0.1,1,tcp,45080,client_to_server,1,2026-10-08T14:44:51.923Z
```

`direction` is `client_to_server` or `server_to_client`; `received` is `1` or `0`; `proto` is `icmp`, `tcp` or `udp` (read `icmp` together with `family`: in IPv6 rows the number is an ICMPv6 type).  `client_addr` is the client's own address on the control connection; if it differs from what the server sees, the client is behind NAT.

`--json` writes the same data as one object: run metadata (`version`, `start`, `end`, `family`, addresses, `timeout_sec`, `directions`), a `results` array with `client_to_server` and `server_to_client` entries (`{"received": bool, "time": ...}` or `null` if not tested), and a `summary`.

## Sample Output

```
Resolved server.example.com -> 192.168.1.50
Connecting to 192.168.1.50 port 1234 (IPv4)
Server ready. Sending 9 probes...

=== chkbounce Report ===
Client: 192.168.1.10  Server: 192.168.1.50  (IPv4)
Direction: client -> server

ICMP Probes:
  Type   0: RECEIVED
  Type   3: not received
  Type   8: RECEIVED

TCP Probes:
  Port    22: RECEIVED
  Port    80: RECEIVED
  Port   443: not received

UDP Probes:
  Port    53: RECEIVED
  Port   123: not received
  Port   161: not received

Summary: client->server 4 of 9 received
```

---

## Limitations

- **One family per session** — To compare IPv4 and IPv6 on a dual-stack path, run the client twice (`-4` and `-6`) against the same server.
- **Sequential clients** — The server handles one client at a time.  A second client must wait until the current session completes.
- **Root required** — Both client and server must run as root (or with `CAP_NET_RAW`) because ICMP probing uses raw sockets.
- **Privileged ports** — Binding TCP or UDP ports below 1024 on the server requires root.
- **NAT** — If the client is behind NAT, the server sees the NAT gateway's IP, which may not match the source IP of raw ICMP packets sent by the client.  TCP and UDP probes are unaffected because the kernel handles their source IP assignment correctly through the NAT mapping.
- **Reverse probes and NAT** — Reverse probes are sent to the client's public (NAT) address, so they will generally not reach a client behind NAT unless the NAT forwards them.
- **Version compatibility** — Client and server should be built from the same version.  `-r` and `-b` need a server built with reverse-probe support (an older server ignores the request and the client hangs), and ICMP probes from a version without sequence-number tagging are not recognized.
- **IPv6 inbound filtering** — IPv6 clients usually have no NAT, but home and enterprise routers commonly block unsolicited inbound traffic, so reverse probes to them may not arrive.
- **Host firewalls** — A firewall on the server machine (e.g., `iptables`, `nftables`) may block probe packets before they reach the listening socket, causing false *not received* results.

---

## License

chkbounce is released under the **GNU General Public License v3.0**.  See the [LICENSE](LICENSE) file for the full text.
