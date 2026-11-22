Local Packet Tracer

A small, single-file network packet viewer written in Go. It captures live TCP and UDP traffic with libpcap and streams it to a web page over WebSocket, where you can browse packets and inspect each one's headers and a hex/ASCII dump.

Everything runs locally: one binary, no external services, and the UI is embedded in the executable.

Features
Live capture of TCP and UDP over IPv4 using a configurable BPF filter
Web UI with a scrolling packet table (protocol, source, destination, length)
Click any packet to see its header details (sequence and ack numbers, window size, TCP flags, UDP length and checksum) and a hex/ASCII dump
Pause, resume and clear controls
Cross-platform: Linux, macOS and Windows (via Npcap)
Security note

This tool streams raw packet data, including payloads, to a local web page and does not restrict which websites can connect to its WebSocket. Only run it on networks you own or are authorized to monitor, and don't leave it running while browsing untrusted sites. Keep the default 127.0.0.1 bind address and never bind it to 0.0.0.0 or a public interface.

Anything sent unencrypted (plain HTTP, FTP, Telnet and similar) is readable in the payload view, including credentials. Capturing traffic requires elevated privileges and, depending on where you run it, may be subject to laws or policies that require authorization.

Requirements
Go 1.22 or newer
A C compiler, because the pcap package uses cgo
libpcap (Linux/macOS) or Npcap (Windows)
Linux (Debian/Ubuntu)
bash
sudo apt install build-essential libpcap-dev

On Fedora/RHEL: sudo dnf install gcc libpcap-devel

macOS
bash
xcode-select --install

libpcap ships with the OS.

Windows
Install Npcap (the runtime).
Install the Npcap SDK (headers and libraries), for example to C:\Npcap-SDK.
Install a MinGW-w64 GCC toolchain (for example via MSYS2 or choco install mingw) and make sure gcc is on your PATH.
Build

Clone the repository and build:

bash
git clone https://github.com/<your-username>/packet-tracer.git
cd packet-tracer
go build -o packet-tracer .

On Windows (PowerShell), point cgo at the Npcap SDK first:

powershell
$env:CGO_ENABLED = "1"
$env:CGO_CFLAGS  = "-IC:\Npcap-SDK\Include"
$env:CGO_LDFLAGS = "-LC:\Npcap-SDK\Lib\x64"
go build -o packet-tracer.exe .

Adjust the paths to match where you installed the SDK. Alternatively, copy the SDK's Include and Lib folders to C:\WpdPack, which is where gopacket looks by default.

Cross-compiling: a plain GOOS=... go build will not work, because cgo needs a native C toolchain and libpcap for the target platform. Build on each operating system you want to support.

Usage

List the available network interfaces:

bash
sudo ./packet-tracer -list

Start capturing on a specific interface:

bash
sudo ./packet-tracer -i eth0

Then open http://127.0.0.1:8080 in your browser.

On Windows, run the terminal as Administrator and use .\packet-tracer.exe.

Options
Flag	Default	Description
-i	auto-detect	Network interface to capture on
-f	tcp or udp	BPF filter expression
-addr	127.0.0.1:8080	Address for the local HTTP/WebSocket server
-list	false	List available interfaces and exit

Examples:

bash
# Only HTTPS traffic
sudo ./packet-tracer -i en0 -f "tcp port 443"

# Traffic to or from one host
sudo ./packet-tracer -i eth0 -f "host 192.168.1.50"

# Use a different port for the web UI
sudo ./packet-tracer -i eth0 -addr 127.0.0.1:9090
Interface names

Names differ by platform: Linux typically uses eth0 or wlan0, macOS uses en0, and Windows uses \Device\NPF_{GUID}. If you don't pass -i, the first non-loopback interface with an address is used. That may not be the one you want (VPN and virtual adapters are common culprits), so run -list and choose explicitly.

Running without sudo on Linux

Instead of running the whole program as root, you can grant the binary only the capture capabilities it needs:

bash
sudo setcap cap_net_raw,cap_net_admin=eip ./packet-tracer
./packet-tracer -i eth0
Limitations
IPv4 only; IPv6 packets are skipped
TCP and UDP only; other protocols (ICMP, ARP and so on) are not displayed
Packets are captured with a 1600-byte snapshot length, so larger payloads are truncated
The browser keeps only the most recent 200 packets
If packets arrive faster than the UI can consume them, the excess is dropped rather than queued
Capturing needs elevated privileges (root, Administrator, or the capabilities above)
Troubleshooting
pcap.h: No such file or directory / cannot find -lpcap: the libpcap (or Npcap SDK) development files are missing. See Requirements.
Error opening device ...: you probably need elevated privileges, or the interface name is wrong. Check it with -list.
cgo: C compiler "gcc" not found: install a C compiler and make sure it's on your PATH.
No packets appear: confirm you picked the right interface, and try a simpler filter such as -f "tcp or udp".
License

MIT. See the LICENSE file for details.
