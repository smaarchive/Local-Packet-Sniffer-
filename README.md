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
