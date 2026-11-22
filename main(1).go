package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/gorilla/websocket"
)

const indexHTML = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Local Packet Tracer</title>
    <style>
        * { box-sizing: border-box; }
        body { font-family: monospace; background: #121212; color: #e0e0e0; margin: 0; display: flex; flex-direction: column; height: 100vh; }
        header { padding: 15px 20px; background: #1a1a1a; border-bottom: 1px solid #333; display: flex; justify-content: space-between; align-items: center; }
        h2 { color: #4caf50; margin: 0; font-size: 18px; }
        .controls { display: flex; gap: 10px; align-items: center; }
        button { background: #333; color: #fff; border: 1px solid #555; padding: 5px 12px; cursor: pointer; font-family: monospace; border-radius: 3px; }
        button:hover { background: #444; }
        .main-container { display: flex; flex: 1; overflow: hidden; }
        .table-pane { flex: 2; overflow-y: auto; border-right: 1px solid #333; }
        .inspector-pane { flex: 1; padding: 15px; background: #181818; overflow-y: auto; display: flex; flex-direction: column; min-width: 420px; }
        table { width: 100%; border-collapse: collapse; font-size: 13px; }
        th, td { padding: 7px 10px; text-align: left; border-bottom: 1px solid #2a2a2a; cursor: pointer; }
        th { background: #252526; color: #888; position: sticky; top: 0; z-index: 1; }
        tr:hover { background: #2a2d2e; }
        tr.selected { background: #264f78 !important; }
        .TCP { color: #64b5f6; font-weight: bold; }
        .UDP { color: #ffb74d; font-weight: bold; }
        .detail-box { background: #222; padding: 12px; border-radius: 4px; margin-bottom: 15px; border: 1px solid #333; font-size: 13px; line-height: 1.5; }
        .hex-dump { font-size: 12px; line-height: 1.5; white-space: pre; background: #111; padding: 10px; border-radius: 4px; border: 1px solid #333; overflow-x: auto; color: #a5d6a7; }
    </style>
</head>
<body>
    <header>
        <h2>Local Network Packet Tracer</h2>
        <div class="controls">
            <button id="pause-btn" onclick="togglePause()">Pause</button>
            <button onclick="clearTable()">Clear</button>
            <span id="status">Connecting...</span>
        </div>
    </header>

    <div class="main-container">
        <div class="table-pane">
            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Time</th>
                        <th>Proto</th>
                        <th>Source</th>
                        <th>Destination</th>
                        <th>Len</th>
                    </tr>
                </thead>
                <tbody id="packet-table"></tbody>
            </table>
        </div>

        <div class="inspector-pane">
            <h3 style="margin-top:0;">Packet Inspector</h3>
            <div id="inspector-details" class="detail-box">Click any packet row to inspect headers and payload.</div>
            <h4 style="margin: 0 0 8px 0;">Hex / ASCII Dump</h4>
            <div id="hex-view" class="hex-dump">No packet selected.</div>
        </div>
    </div>

    <script>
        const statusEl = document.getElementById("status");
        const pauseBtn = document.getElementById("pause-btn");
        const tableBody = document.getElementById("packet-table");
        const detailsEl = document.getElementById("inspector-details");
        const hexViewEl = document.getElementById("hex-view");
        const ws = new WebSocket("ws://" + window.location.host + "/ws");

        let selectedRow = null;
        let isPaused = false;

        ws.onopen = () => { statusEl.textContent = "Connected (Live)"; statusEl.style.color = "#4caf50"; };
        ws.onclose = () => { statusEl.textContent = "Disconnected"; statusEl.style.color = "#f44336"; };

        function togglePause() {
            isPaused = !isPaused;
            pauseBtn.textContent = isPaused ? "Resume" : "Pause";
            statusEl.textContent = isPaused ? "Paused" : "Connected (Live)";
            statusEl.style.color = isPaused ? "#ffb74d" : "#4caf50";
        }

        function clearTable() {
            tableBody.innerHTML = "";
            detailsEl.innerHTML = "Click any packet row to inspect headers and payload.";
            hexViewEl.textContent = "No packet selected.";
        }

        ws.onmessage = (event) => {
            if (isPaused) return;
            const pkt = JSON.parse(event.data);
            const row = document.createElement("tr");

            row.innerHTML =
                "<td>" + pkt.id + "</td>" +
                "<td>" + pkt.timestamp + "</td>" +
                "<td class=\"" + pkt.protocol + "\">" + pkt.protocol + "</td>" +
                "<td>" + pkt.src + "</td>" +
                "<td>" + pkt.dst + "</td>" +
                "<td>" + pkt.length + " B</td>";

            row.onclick = () => inspectPacket(pkt, row);

            tableBody.insertBefore(row, tableBody.firstChild);
            if (tableBody.children.length > 200) {
                tableBody.removeChild(tableBody.lastChild);
            }
        };

        function inspectPacket(pkt, rowElement) {
            if (selectedRow) selectedRow.classList.remove("selected");
            rowElement.classList.add("selected");
            selectedRow = rowElement;

            detailsEl.innerHTML =
                "<strong>Packet #" + pkt.id + "</strong> (" + pkt.length + " bytes)<br>" +
                "<strong>Timestamp:</strong> " + pkt.timestamp + "<br>" +
                "<strong>Flow:</strong> " + pkt.src + " &rarr; " + pkt.dst + "<br>" +
                "<strong>Protocol:</strong> " + pkt.protocol + "<br>" +
                "<strong>Header Info:</strong> " + pkt.info;

            hexViewEl.textContent = formatHexDump(pkt.raw_bytes);
        }

        function formatHexDump(base64Str) {
            const binary = atob(base64Str);
            let output = "";
            for (let i = 0; i < binary.length; i += 16) {
                const offset = i.toString(16).padStart(4, "0");
                let hexPart = "";
                let asciiPart = "";

                for (let j = 0; j < 16; j++) {
                    if (i + j < binary.length) {
                        const code = binary.charCodeAt(i + j);
                        hexPart += code.toString(16).padStart(2, "0") + " ";
                        asciiPart += (code >= 32 && code <= 126) ? binary[i + j] : ".";
                    } else {
                        hexPart += "   ";
                    }
                    if (j === 7) hexPart += " ";
                }
                output += offset + "  " + hexPart + " |" + asciiPart + "|\n";
            }
            return output;
        }
    </script>
</body>
</html>`

type PacketSummary struct {
	ID        int    `json:"id"`
	Timestamp string `json:"timestamp"`
	Protocol  string `json:"protocol"`
	Src       string `json:"src"`
	Dst       string `json:"dst"`
	Length    int    `json:"length"`
	Info      string `json:"info"`
	RawBytes  []byte `json:"raw_bytes"`
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}
	clients   = make(map[*websocket.Conn]bool)
	clientsMu sync.Mutex
	broadcast = make(chan PacketSummary, 1000)
)

func main() {
	iface := flag.String("i", "", "Network interface name (leave empty to auto-detect or list)")
	filter := flag.String("f", "tcp or udp", "BPF packet filter expression")
	addr := flag.String("addr", "127.0.0.1:8080", "Local HTTP/WebSocket bind address")
	listDevs := flag.Bool("list", false, "List available network interfaces and exit")
	flag.Parse()

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatalf("Error finding network devices: %v", err)
	}

	if *listDevs {
		fmt.Println("Available Network Interfaces:")
		for _, d := range devices {
			fmt.Printf("  - Name: %s | Description: %s\n", d.Name, d.Description)
		}
		return
	}

	targetIface := *iface
	if targetIface == "" {
		for _, d := range devices {
			if len(d.Addresses) > 0 && d.Name != "lo" && d.Name != "lo0" {
				targetIface = d.Name
				break
			}
		}
		if targetIface == "" && len(devices) > 0 {
			targetIface = devices[0].Name
		}
	}

	if targetIface == "" {
		log.Fatal("No network interfaces found. Run with sudo/Administrator privileges.")
	}

	go startPacketCapture(targetIface, *filter)
	go handleBroadcasts()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(indexHTML))
	})
	http.HandleFunc("/ws", handleConnections)

	server := &http.Server{Addr: *addr}
	go func() {
		fmt.Printf("Capturing on interface: %s (Filter: %q)\n", targetIface, *filter)
		fmt.Printf("Packet Tracer UI running at http://%s\n", *addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	fmt.Println("\nShutting down Packet Tracer...")
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer ws.Close()

	clientsMu.Lock()
	clients[ws] = true
	clientsMu.Unlock()

	for {
		if _, _, err := ws.ReadMessage(); err != nil {
			clientsMu.Lock()
			delete(clients, ws)
			clientsMu.Unlock()
			break
		}
	}
}

func handleBroadcasts() {
	for pkt := range broadcast {
		clientsMu.Lock()
		for client := range clients {
			if err := client.WriteJSON(pkt); err != nil {
				client.Close()
				delete(clients, client)
			}
		}
		clientsMu.Unlock()
	}
}

func startPacketCapture(deviceName string, bpfFilter string) {
	handle, err := pcap.OpenLive(deviceName, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatalf("Error opening device %s: %v", deviceName, err)
	}
	defer handle.Close()

	if bpfFilter != "" {
		if err := handle.SetBPFFilter(bpfFilter); err != nil {
			log.Fatalf("Error setting BPF filter %q: %v", bpfFilter, err)
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetID := 0

	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}
		ip, _ := ipLayer.(*layers.IPv4)

		var proto, srcPort, dstPort, info string
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)
			proto = "TCP"
			srcPort = tcp.SrcPort.String()
			dstPort = tcp.DstPort.String()
			info = fmt.Sprintf("Seq=%d Ack=%d Win=%d [SYN:%v ACK:%v FIN:%v PSH:%v]",
				tcp.Seq, tcp.Ack, tcp.Window, tcp.SYN, tcp.ACK, tcp.FIN, tcp.PSH)
		} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			proto = "UDP"
			srcPort = udp.SrcPort.String()
			dstPort = udp.DstPort.String()
			info = fmt.Sprintf("Len=%d Checksum=0x%x", udp.Length, udp.Checksum)
		} else {
			continue
		}

		packetID++
		rawCopy := make([]byte, len(packet.Data()))
		copy(rawCopy, packet.Data())

		summary := PacketSummary{
			ID:        packetID,
			Timestamp: packet.Metadata().Timestamp.Format("15:04:05.000"),
			Protocol:  proto,
			Src:       fmt.Sprintf("%s:%s", ip.SrcIP, srcPort),
			Dst:       fmt.Sprintf("%s:%s", ip.DstIP, dstPort),
			Length:    len(rawCopy),
			Info:      info,
			RawBytes:  rawCopy,
		}

		select {
		case broadcast <- summary:
		default:
		}
	}
}
