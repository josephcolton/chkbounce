# chkbounce

**chkbounce** is a network diagnostic tool that determines which types of traffic can traverse the path between two hosts.  It operates in a client/server model: a persistent server process listens for incoming client connections, negotiates a set of probes, and reports back in real time which packets it received.  Supported probe types are **ICMP** (all 256 type numbers or a specific subset), **TCP** (by port number), and **UDP** (by port number).

---

## Features

- Tests ICMP reachability across all 256 type numbers, or any subset/range
- Tests TCP port reachability by attempting connections
- Tests UDP reachability by sending datagrams
- Flexible range syntax for specifying what to probe (`22,25-30,80,443`)
- Per-probe configurable timeout
- Server runs persistently and handles multiple client sessions sequentially
- Client accepts both hostnames and IPv4 addresses for the server
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

`SERVER` may be either a hostname (resolved via DNS) or a dotted-decimal IPv4 address.

---

## Options

| Option | Description |
|--------|-------------|
| `-s`, `--server` | Run in server mode |
| `-c`, `--client` | Run in client mode |
| `-p NUM`, `--port=NUM` | TCP port used for the control channel (default: **1234**) |
| `--timeout=NUM` | Per-probe timeout in seconds (default: **2**) |
| `-i[TYPES]`, `--icmp[=TYPES]` | Enable ICMP probes.  `TYPES` is a range list of ICMP type numbers (0–255).  Omit `TYPES` to probe all 256 types. |
| `-t[PORTS]`, `--tcp[=PORTS]` | Enable TCP probes.  `PORTS` is a range list of port numbers.  Omit `PORTS` to use the default port list. |
| `-u[PORTS]`, `--udp[=PORTS]` | Enable UDP probes.  `PORTS` is a range list of port numbers.  Omit `PORTS` to use the default port list. |
| `-o FILE`, `--output=FILE` | Write the final report to `FILE` in addition to printing it to stdout.  The file is created or overwritten.  Progress and connection messages are not written to the file. |

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
4. **Done** — After the last probe the client sends a *done* message, the server closes the client session, and the server loops back to accept the next incoming client.

### Per-probe socket lifecycle

Opening one socket per probe (rather than all sockets up front during negotiation) avoids hitting per-process file-descriptor limits even when testing thousands of ports.  The ICMP raw socket is an exception: it is opened once at the start of a client session and reused for all ICMP probes, then closed when the session ends.

### ICMP filtering

The server uses a single `SOCK_RAW / IPPROTO_ICMP` socket and filters incoming packets by the client's source IP address (taken from the control-channel TCP connection) and the expected ICMP type number.  Unrelated ICMP traffic arriving during a probe window is silently discarded.

### Probe methods

| Protocol | Client action | Server action |
|----------|--------------|---------------|
| ICMP | Sends a raw ICMP packet with the requested type number | Receives on a raw ICMP socket; filters by source IP and type |
| TCP | Non-blocking `connect()` to the server's port | `accept()` on a listening socket |
| UDP | Sends a small datagram to the server's port | `recvfrom()` on a bound socket; filters by source IP |

---

## Sample Output

```
Resolved server.example.com -> 192.168.1.50
Connecting to 192.168.1.50:1234
Server ready. Sending 9 probes...

=== chkbounce Report ===

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

Summary: 4 of 9 probes received
```

---

## Limitations

- **IPv4 only** — IPv6 is not supported.
- **Sequential clients** — The server handles one client at a time.  A second client must wait until the current session completes.
- **Root required** — Both client and server must run as root (or with `CAP_NET_RAW`) because ICMP probing uses raw sockets.
- **Privileged ports** — Binding TCP or UDP ports below 1024 on the server requires root.
- **NAT** — If the client is behind NAT, the server sees the NAT gateway's IP, which may not match the source IP of raw ICMP packets sent by the client.  TCP and UDP probes are unaffected because the kernel handles their source IP assignment correctly through the NAT mapping.
- **Host firewalls** — A firewall on the server machine (e.g., `iptables`, `nftables`) may block probe packets before they reach the listening socket, causing false *not received* results.

---

## License

chkbounce is released under the **GNU General Public License v3.0**.  See the [LICENSE](LICENSE) file for the full text.
