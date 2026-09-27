package main

// Pcap generators for testdata/scenarios. Each writes realistic traffic
// (correct sequence numbers, both directions) with pcapgen. Addresses come
// from the documentation ranges: 192.0.2.0/24 servers, 203.0.113.0/24
// attackers, 10.0.0.0/8 clients, 198.18.0.0/15 spoofed sources.

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/bUrn-1337/intrusion-detection-system/internal/testutil/pcapgen"
)

// genSYNFloodSingleSource: 203.0.113.5 sends 300 SYNs to a closed port on
// 192.0.2.10 in 1.2s; each is refused. A client's normal HTTP connection
// runs alongside.
func genSYNFloodSingleSource(w *pcapgen.Writer) {
	w.Step = 2 * time.Millisecond
	web := w.Conn("10.0.0.20", 50000, "192.0.2.10", 80)
	web.Handshake()
	for i := 0; i < 300; i++ {
		c := w.Conn("203.0.113.5", uint16(40000+i), "192.0.2.10", 8081)
		c.SYN()
		c.Refuse()
		if i == 150 {
			web.Send(true, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
			web.Send(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	}
	web.Close()
}

// genSYNFloodSpoofed: 300 SYNs from 300 different spoofed sources to
// 192.0.2.10:80 within 1.5s. The server answers SYN/ACK; nobody completes
// the handshake. Five real clients complete theirs.
func genSYNFloodSpoofed(w *pcapgen.Writer) {
	w.Step = 2500 * time.Microsecond
	for i := 0; i < 300; i++ {
		src := fmt.Sprintf("198.18.%d.%d", i/200, i%200+1)
		c := w.Conn(src, uint16(1024+i*7), "192.0.2.10", 80)
		c.SYN()
		c.SYNACK()
		if i%60 == 0 {
			real := w.Conn(fmt.Sprintf("10.0.1.%d", i/60+1), 51000, "192.0.2.10", 80)
			real.Handshake()
			real.Close()
		}
	}
	// Retransmission timeouts pass; the half-open handshakes expire.
	w.Wait(5 * time.Second)
	w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.1.1", Dst: "192.0.2.53", Sport: 5353, Dport: 5353, Payload: []byte("tick")})
}

// genCompletedHandshakesBusy: 20 clients open 600 HTTPS connections to one
// server in about 4s (150/s), all completing. Alongside, 120 connections
// to a closed port are refused: enough failures to pass the count of 100
// in 5s, so only the incomplete ratio (120/720) keeps the rule quiet.
func genCompletedHandshakesBusy(w *pcapgen.Writer) {
	w.Step = 500 * time.Microsecond
	hello := pcapgen.TLSClientHello("shop.example.test")
	for i := 0; i < 600; i++ {
		c := w.Conn(fmt.Sprintf("10.1.0.%d", i%20+1), uint16(40000+i), "192.0.2.20", 443)
		c.Handshake()
		c.Send(true, hello)
		c.Send(false, []byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0}) // ServerHello stub
		c.Close()
		if i%5 == 0 {
			r := w.Conn(fmt.Sprintf("10.1.0.%d", i%20+1), uint16(30000+i), "192.0.2.20", 8443)
			r.SYN()
			r.Refuse()
		}
	}
}

// genDNSAXFR: a client asks a name server for a zone transfer over TCP
// (refused), next to ordinary UDP lookups.
func genDNSAXFR(w *pcapgen.Writer) {
	for i, name := range []string{"www.example.test", "mail.example.test"} {
		id := uint16(100 + i)
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.5", Dst: "192.0.2.53", Sport: 53000, Dport: 53, Payload: pcapgen.DNSQuery(id, name, 1)})
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "192.0.2.53", Dst: "10.0.0.5", Sport: 53, Dport: 53000, Payload: pcapgen.DNSAnswerA(id, name, [4]byte{192, 0, 2, 80})})
	}
	c := w.Conn("10.0.0.5", 41000, "192.0.2.53", 53)
	c.Handshake()
	q := pcapgen.DNSQuery(0x4242, "example.test", 252)
	c.Send(true, pcapgen.TCPDNS(q))
	refused := append([]byte(nil), q...)
	refused[2], refused[3] = 0x81, 0x05 // QR RD, REFUSED
	c.Send(false, pcapgen.TCPDNS(refused))
	c.Close()
}

// genDNSMalformedLoop: three responses whose question name is a
// compression pointer to itself (C0 0C), which would loop a naive decoder
// forever. The parser decodes only the question section, so that is where
// the loop has to be.
func genDNSMalformedLoop(w *pcapgen.Writer) {
	for i := 0; i < 3; i++ {
		id := uint16(200 + i)
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.5", Dst: "192.0.2.53", Sport: uint16(53100 + i), Dport: 53, Payload: pcapgen.DNSQuery(id, "loop.example.test", 1)})
		m := binary.BigEndian.AppendUint16(nil, id)
		m = append(m, 0x81, 0x80, 0, 1, 0, 0, 0, 0, 0, 0) // response, qd=1
		m = append(m, 0xC0, 12)                           // qname: pointer to offset 12, itself
		m = append(m, 0, 1, 0, 1)
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "192.0.2.53", Dst: "10.0.0.5", Sport: 53, Dport: uint16(53100 + i), Payload: m})
	}
}

// genHTTPBasicAuth: a client logs in to an admin page with Basic auth
// (admin:hunter2) over plain HTTP.
func genHTTPBasicAuth(w *pcapgen.Writer) {
	c := w.Conn("10.0.0.7", 42000, "192.0.2.80", 80)
	c.Handshake()
	c.Send(true, []byte("GET /admin/ HTTP/1.1\r\nHost: router.example.test\r\nAuthorization: Basic YWRtaW46aHVudGVyMg==\r\nUser-Agent: curl/8.5.0\r\n\r\n"))
	c.Send(false, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 5\r\n\r\nhello"))
	c.Close()
}

// genHTTPDoubleEncoding: a path traversal attempt hidden with %252e/%252f
// (decodes to %2e/%2f, then to ./), after a normal request. Another client
// first sends an ad-click URL that is double-encoded but hides no
// traversal, which must not alert.
func genHTTPDoubleEncoding(w *pcapgen.Writer) {
	b := w.Conn("10.0.0.12", 43100, "192.0.2.80", 80)
	b.Handshake()
	b.Send(true, []byte("GET /ad/336x280.swf?clickTag=http%3A//ad.example.test/click%253Bh%3Dv8/3/0/%252a/a%253B2194%253B0-0%253B0%253B%257Eokv%253D%253Bu%253Dhttp%253A%252F%252Fshop.example.test%252F HTTP/1.1\r\nHost: www.example.test\r\n\r\n"))
	b.Send(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	b.Close()

	c := w.Conn("203.0.113.9", 43000, "192.0.2.80", 80)
	c.Handshake()
	c.Send(true, []byte("GET /index.html HTTP/1.1\r\nHost: www.example.test\r\n\r\n"))
	c.Send(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
	c.Send(true, []byte("GET /static/%252e%252e%252f%252e%252e%252fetc%252fpasswd HTTP/1.1\r\nHost: www.example.test\r\n\r\n"))
	c.Send(false, []byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n"))
	c.Close()
}

// ftpLogin writes USER/331/PASS/reply on an FTP control connection.
func ftpLogin(c *pcapgen.Conn, user, pass, reply string) {
	c.Send(true, []byte("USER "+user+"\r\n"))
	c.Send(false, []byte("331 Password required for "+user+"\r\n"))
	c.Send(true, []byte("PASS "+pass+"\r\n"))
	c.Send(false, []byte(reply+"\r\n"))
}

// genFTPBruteforce: an attacker tries 8 passwords, one per second, on one
// control connection; every attempt gets 530.
func genFTPBruteforce(w *pcapgen.Writer) {
	c := w.Conn("203.0.113.66", 44000, "192.0.2.21", 21)
	c.Handshake()
	c.Send(false, []byte("220 FTP server ready\r\n"))
	for i := 1; i <= 8; i++ {
		ftpLogin(c, "admin", fmt.Sprintf("guess%dpw", i), "530 Login incorrect.")
		w.Wait(time.Second)
	}
	c.Close()
}

// genFTPPlaintextPass: one successful FTP login and logout.
func genFTPPlaintextPass(w *pcapgen.Writer) {
	c := w.Conn("10.0.0.8", 45000, "192.0.2.21", 21)
	c.Handshake()
	c.Send(false, []byte("220 FTP server ready\r\n"))
	ftpLogin(c, "alice", "s3cretPw!", "230 User alice logged in.")
	c.Send(true, []byte("PWD\r\n"))
	c.Send(false, []byte("257 \"/home/alice\" is the current directory\r\n"))
	c.Send(true, []byte("QUIT\r\n"))
	c.Send(false, []byte("221 Goodbye.\r\n"))
	c.Close()
}

// genBenignMixed: a minute of ordinary client activity: DNS lookups, web
// browsing over HTTP and HTTPS (including a URI with a single-encoded
// "%25"), pings, and a TLS session over IPv6.
func genBenignMixed(w *pcapgen.Writer) {
	w.Step = 3 * time.Millisecond
	names := []string{"www.example.test", "cdn.example.test", "api.example.test", "news.example.test", "mail.example.test", "img.example.test"}
	port := uint16(50000)
	for round := 0; round < 10; round++ {
		for i, name := range names {
			id := uint16(round*len(names) + i)
			w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.10", Dst: "192.0.2.53", Sport: 33000 + id, Dport: 53, Payload: pcapgen.DNSQuery(id, name, 1)})
			w.Add(pcapgen.Pkt{Proto: "udp", Src: "192.0.2.53", Dst: "10.0.0.10", Sport: 53, Dport: 33000 + id, Payload: pcapgen.DNSAnswerA(id, name, [4]byte{192, 0, 2, byte(100 + i)})})

			port++
			server := fmt.Sprintf("192.0.2.%d", 100+i)
			if i%2 == 0 {
				c := w.Conn("10.0.0.10", port, server, 80)
				c.Handshake()
				c.Send(true, []byte("GET /search?q=50%25+off&page="+fmt.Sprint(round)+" HTTP/1.1\r\nHost: "+name+"\r\nAccept: */*\r\n\r\n"))
				c.Send(false, []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nok"))
				c.Close()
			} else {
				c := w.Conn("10.0.0.10", port, server, 443)
				c.Handshake()
				c.Send(true, pcapgen.TLSClientHello(name))
				c.Send(false, []byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0})
				c.Send(true, []byte{0x17, 3, 3, 0, 3, 1, 2, 3})
				c.Close()
			}
		}
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "10.0.0.10", Dst: "192.0.2.1"})
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "fd00::10", Dst: "fd00::1"})
		v6 := w.Conn("fd00::10", 60000+uint16(round), "fd00::443", 443)
		v6.Handshake()
		v6.Send(true, pcapgen.TLSClientHello("v6.example.test"))
		v6.Close()
		w.Wait(5 * time.Second)
	}
	// An NTP exchange: UDP on a port with no parser.
	ntp := make([]byte, 48)
	ntp[0] = 0x23
	binary.BigEndian.PutUint32(ntp[40:], 0xe8f0_0000)
	w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.10", Dst: "192.0.2.123", Sport: 123, Dport: 123, Payload: ntp})
}

// Scan scenarios. The scanner is 203.0.113.50 and the scanned host
// 192.0.2.10; closed TCP ports answer RST/ACK as real stacks do.

const (
	genScanner = "203.0.113.50"
	genTarget  = "192.0.2.10"
)

// scanOrder is a scanner's port order: common ports first, then the rest
// of 1..n.
func scanOrder(n int) []uint16 {
	first := []uint16{80, 23, 443, 21, 22, 25, 3389, 110, 445, 139, 143, 53, 135, 3306, 8080, 1723, 111, 995, 993, 5900}
	seen := map[uint16]bool{}
	var out []uint16
	for _, p := range first {
		if int(p) <= n {
			out, seen[p] = append(out, p), true
		}
	}
	for p := uint16(1); int(p) <= n; p++ {
		if !seen[p] {
			out = append(out, p)
		}
	}
	return out
}

// synProbe writes one SYN scan probe: open ports answer SYN/ACK and the
// scanner resets (half-open), closed ports answer RST/ACK.
func synProbe(w *pcapgen.Writer, src string, sport uint16, dst string, port uint16, open bool) {
	c := w.Conn(src, sport, dst, port)
	c.SYN()
	if !open {
		c.Refuse()
		return
	}
	c.SYNACK()
	w.Add(pcapgen.Pkt{Proto: "tcp", Src: src, Dst: dst, Sport: sport, Dport: port, Flags: "R", Seq: 1001})
}

// genVerticalSYNScan: 203.0.113.50 SYN-scans ports 1-1000 of 192.0.2.10
// in about 3s (nmap -sS order: common ports first). 22, 80 and 443 are
// open. A client's HTTP connection runs alongside.
func genVerticalSYNScan(w *pcapgen.Writer) {
	w.Step = time.Millisecond
	web := w.Conn("10.0.0.20", 50000, genTarget, 80)
	web.Handshake()
	for i, p := range scanOrder(1000) {
		synProbe(w, genScanner, 45000, genTarget, p, p == 22 || p == 80 || p == 443)
		if i == 500 {
			web.Send(true, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
			web.Send(false, []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
		}
	}
	web.Close()
}

// genFlagScan: 203.0.113.50 sends one TCP packet with flags to ports
// 1-100 of 192.0.2.10. Closed ports answer RST/ACK; open ports (22, 80)
// stay silent, which is how FIN, NULL and Xmas scans tell them apart.
func genFlagScan(flags string) func(w *pcapgen.Writer) {
	return func(w *pcapgen.Writer) {
		w.Step = 2 * time.Millisecond
		ack := uint32(1000)
		if strings.Contains(flags, "F") {
			ack++ // FIN takes a sequence number
		}
		for _, p := range scanOrder(100) {
			w.Add(pcapgen.Pkt{Proto: "tcp", Src: genScanner, Dst: genTarget, Sport: 45001, Dport: p, Flags: flags, Seq: 1000})
			if p != 22 && p != 80 {
				w.Add(pcapgen.Pkt{Proto: "tcp", Src: genTarget, Dst: genScanner, Sport: p, Dport: 45001, Flags: "RA", Ack: ack})
			}
		}
	}
}

// genSYNFINPacket: 203.0.113.60 sends two SYN+FIN packets to
// 192.0.2.10:80 (an old firewall-evasion trick); the server answers the
// first with RST/ACK. Too few ports for a scan.
func genSYNFINPacket(w *pcapgen.Writer) {
	for i := range 2 {
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: "203.0.113.60", Dst: genTarget, Sport: 40000 + uint16(i), Dport: 80, Flags: "SF", Seq: 7000})
		if i == 0 {
			w.Add(pcapgen.Pkt{Proto: "tcp", Src: genTarget, Dst: "203.0.113.60", Sport: 80, Dport: 40000, Flags: "RA", Ack: 7001})
		}
	}
	c := w.Conn("10.0.0.20", 50001, genTarget, 80)
	c.Handshake()
	c.Close()
}

// genUDPScan: 203.0.113.50 sends empty UDP datagrams to ports 1-60 of
// 192.0.2.10. Closed ports answer ICMP port unreachable; 53 answers (a
// DNS server) and 7 stays silent (open or filtered). The same happens
// over IPv6 for ports 1-10 (too few for an alert on their own; the
// IPv6 source is a different scanner address).
func genUDPScan(w *pcapgen.Writer) {
	w.Step = 5 * time.Millisecond
	for _, p := range scanOrder(60) {
		probe := pcapgen.Pkt{Proto: "udp", Src: genScanner, Dst: genTarget, Sport: 45002, Dport: p}
		w.Add(probe)
		switch p {
		case 53:
			w.Add(pcapgen.Pkt{Proto: "udp", Src: genTarget, Dst: genScanner, Sport: 53, Dport: 45002, Payload: pcapgen.DNSAnswerA(0, "x.test", [4]byte{192, 0, 2, 1})})
		case 7:
		default:
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: genTarget, Dst: genScanner, Unreach: &probe})
		}
	}
	for p := uint16(1); p <= 10; p++ {
		probe := pcapgen.Pkt{Proto: "udp", Src: "2001:db8::50", Dst: "2001:db8::10", Sport: 45002, Dport: p}
		w.Add(probe)
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "2001:db8::10", Dst: "2001:db8::50", Unreach: &probe})
	}
}

// genHorizontalSweep22: 203.0.113.50 SYN-probes port 22 on 192.0.2.1-40
// in 2s. Every tenth host has SSH open (half-open probe), every third
// is filtered (no answer; the handshake times out), the rest refuse.
func genHorizontalSweep22(w *pcapgen.Writer) {
	w.Step = 25 * time.Millisecond
	for i := 1; i <= 40; i++ {
		host := fmt.Sprintf("192.0.2.%d", i)
		if i%3 == 0 && i%10 != 0 {
			w.Conn(genScanner, 45003, host, 22).SYN()
			continue
		}
		synProbe(w, genScanner, 45003, host, 22, i%10 == 0)
	}
	// The filtered handshakes time out.
	w.Wait(10 * time.Second)
	w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.20", Dst: "192.0.2.53", Sport: 5353, Dport: 5353, Payload: []byte("tick")})
}

// genPingSweep: 203.0.113.50 sends Echo Requests to 192.0.2.1-30 in 3s.
// A client pings its gateway alongside.
func genPingSweep(w *pcapgen.Writer) {
	w.Step = 100 * time.Millisecond
	for i := 1; i <= 30; i++ {
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: genScanner, Dst: fmt.Sprintf("192.0.2.%d", i)})
		if i%5 == 0 {
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: "10.0.0.20", Dst: "10.0.0.1"})
		}
	}
}

// genScanIsNotFlood: 1000 SYNs from 203.0.113.50 to 1000 different ports
// on 192.0.2.10 in about 1s, all refused. Over syn_flood's count and
// ratio, but spread over 1000 ports.
func genScanIsNotFlood(w *pcapgen.Writer) {
	w.Step = 500 * time.Microsecond
	for p := uint16(1); p <= 1000; p++ {
		synProbe(w, genScanner, 45004, genTarget, p, false)
	}
}

// genFloodIsNotScan: 1000 SYNs from 203.0.113.50 (1000 source ports) to
// 192.0.2.10:80 in about 1s, answered with SYN/ACK and never completed.
func genFloodIsNotScan(w *pcapgen.Writer) {
	w.Step = 500 * time.Microsecond
	for i := range 1000 {
		c := w.Conn(genScanner, 20000+uint16(i), genTarget, 80)
		c.SYN()
		c.SYNACK()
	}
	w.Wait(10 * time.Second)
	w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.20", Dst: "192.0.2.53", Sport: 5353, Dport: 5353, Payload: []byte("tick")})
}

// genBrowsingManyHosts: a client looks up and opens HTTPS connections to
// 40 different servers (192.0.2.101-140) in 8s, all completing.
func genBrowsingManyHosts(w *pcapgen.Writer) {
	w.Step = 2 * time.Millisecond
	for i := range 40 {
		name := fmt.Sprintf("site%d.example.test", i)
		id := uint16(i)
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.30", Dst: "192.0.2.53", Sport: 34000 + id, Dport: 53, Payload: pcapgen.DNSQuery(id, name, 1)})
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "192.0.2.53", Dst: "10.0.0.30", Sport: 53, Dport: 34000 + id, Payload: pcapgen.DNSAnswerA(id, name, [4]byte{192, 0, 2, byte(101 + i)})})
		c := w.Conn("10.0.0.30", 51000+id, fmt.Sprintf("192.0.2.%d", 101+i), 443)
		c.Handshake()
		c.Send(true, pcapgen.TLSClientHello(name))
		c.Send(false, []byte{0x16, 3, 3, 0, 4, 2, 0, 0, 0})
		c.Close()
		w.Wait(200 * time.Millisecond)
	}
}

// genIDSStartedMidConnection: the capture starts while a client has 60
// connections open to 30 servers on 30 ports. Each ends with FIN/ACK,
// FIN/ACK, ACK (a few with a last data segment or an RST); the IDS never
// saw their handshakes.
func genIDSStartedMidConnection(w *pcapgen.Writer) {
	w.Step = time.Millisecond
	for i := range 60 {
		client, cport := "10.0.0.40", 52000+uint16(i)
		server, sport := fmt.Sprintf("192.0.2.%d", 150+i%30), 8000+uint16(i%30)
		seq, ack := uint32(900000+i*1000), uint32(700000+i*1000)
		if i%4 == 0 {
			w.Add(pcapgen.Pkt{Proto: "tcp", Src: server, Dst: client, Sport: sport, Dport: cport, Flags: "PA", Seq: ack, Ack: seq, Payload: []byte("bye")})
			ack += 3
		}
		if i%10 == 9 {
			w.Add(pcapgen.Pkt{Proto: "tcp", Src: client, Dst: server, Sport: cport, Dport: sport, Flags: "RA", Seq: seq, Ack: ack})
			continue
		}
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: client, Dst: server, Sport: cport, Dport: sport, Flags: "FA", Seq: seq, Ack: ack})
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: server, Dst: client, Sport: sport, Dport: cport, Flags: "FA", Seq: ack, Ack: seq + 1})
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: client, Dst: server, Sport: cport, Dport: sport, Flags: "A", Seq: seq + 1, Ack: ack + 1})
	}
}

// ---------------------------------------------------------------------
// Land, smurf, ICMP recon, TTL and fragment scenarios. 198.51.100.0/24
// is an external host that the TTL detector learns.

// genLandAttack: three land SYNs (192.0.2.10:139 to itself) among normal
// traffic to that server.
func genLandAttack(w *pcapgen.Writer) {
	w.Step = 50 * time.Millisecond
	c := w.Conn("10.0.0.20", 50100, "192.0.2.10", 80)
	c.Handshake()
	for i := range 3 {
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: "192.0.2.10", Dst: "192.0.2.10", Sport: 139, Dport: 139, Flags: "S", Seq: uint32(1000 + i)})
	}
	c.Send(true, []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
	c.Close()
}

// genLandIPOnly: two UDP datagrams with the same source and destination
// address but different ports, and loopback traffic (127.0.0.1 to itself,
// as seen on lo), which must not fire.
func genLandIPOnly(w *pcapgen.Writer) {
	w.Step = 10 * time.Millisecond
	for range 2 {
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "192.0.2.10", Dst: "192.0.2.10", Sport: 1234, Dport: 7, Payload: []byte("land")})
	}
	z := pcapgen.ZeroMAC // Linux loopback frames
	for i := range 10 {
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "127.0.0.1", Dst: "127.0.0.1", Sport: 40000 + uint16(i), Dport: 53, Payload: pcapgen.DNSQuery(uint16(i), "example.test", 1), EthSrc: z, EthDst: z})
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: "::1", Dst: "::1", Sport: 41000 + uint16(i), Dport: 8080, Flags: "S", EthSrc: z, EthDst: z})
	}
}

// genWSLDNSProxyLoopback: the WSL2 DNS proxy as captured on lo. Queries
// and answers go from 10.255.255.254 to itself (ephemeral port <-> 53),
// in loopback frames with all-zero MACs; 20 lookups, 2 s apart.
func genWSLDNSProxyLoopback(w *pcapgen.Writer) {
	z := pcapgen.ZeroMAC
	const proxy = "10.255.255.254"
	for i := range 20 {
		port := 40000 + uint16(i)*7
		w.Step = 60 * time.Microsecond
		w.Add(pcapgen.Pkt{Proto: "udp", Src: proxy, Dst: proxy, Sport: port, Dport: 53, Payload: pcapgen.DNSQuery(uint16(i), "www.example.com", 1), EthSrc: z, EthDst: z})
		w.Step = 2 * time.Second
		w.Add(pcapgen.Pkt{Proto: "udp", Src: proxy, Dst: proxy, Sport: 53, Dport: port, Payload: pcapgen.DNSAnswerA(uint16(i), "www.example.com", [4]byte{93, 184, 215, 14}), EthSrc: z, EthDst: z})
	}
	// A TCP SYN to itself on the same port (as a land packet would be),
	// still on lo.
	w.Add(pcapgen.Pkt{Proto: "tcp", Src: proxy, Dst: proxy, Sport: 53, Dport: 53, Flags: "S", EthSrc: z, EthDst: z})
}

// genTTLLoadBalancedConns reproduces the eth0.pcap false positive: one
// external server (203.0.113.80:443) answers five connections from
// 10.0.0.5, 10 s apart, each routed over its own path (per-connection
// ECMP or a different load-balancer node). TTLs 50, 43, 57, 36 and 62
// give distances 14, 21, 7, 28 and 2: stable within a connection, more
// than 3 hops apart between any two. Each connection completes its
// handshake and the server sends 12 data segments, so every distance
// gets established (min_samples 10).
func genTTLLoadBalancedConns(w *pcapgen.Writer) {
	w.Step = 20 * time.Millisecond
	for i, ttl := range []uint8{50, 43, 57, 36, 62} {
		c := w.Conn("10.0.0.5", 50000+uint16(i), "203.0.113.80", 443)
		c.ServerTTL = ttl
		c.Handshake()
		c.Send(true, []byte("GET / HTTP/1.1\r\nHost: lb.example\r\n\r\n"))
		for range 12 {
			c.Send(false, make([]byte, 1000))
		}
		c.Close()
		w.Wait(10 * time.Second)
	}
}

// genSmurfBroadcastMAC: 20 Echo Requests with the victim 192.0.2.50 as
// spoofed source, sent to the directed broadcast 192.168.1.255 (Ethernet
// broadcast); five hosts on the segment answer each to the victim.
func genSmurfBroadcastMAC(w *pcapgen.Writer) {
	w.Step = 5 * time.Millisecond
	for range 20 {
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "192.0.2.50", Dst: "192.168.1.255", EthDst: pcapgen.Broadcast, Payload: make([]byte, 56)})
		for h := range 5 {
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: fmt.Sprintf("192.168.1.%d", 10+h), Dst: "192.0.2.50", ICMP: &[2]uint8{0, 0}, Payload: make([]byte, 60)})
		}
	}
}

// genSmurfLimitedBroadcast: 5 Echo Requests from the spoofed victim to
// 255.255.255.255, which always goes to the Ethernet broadcast address.
func genSmurfLimitedBroadcast(w *pcapgen.Writer) {
	w.Step = 100 * time.Millisecond
	for range 5 {
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "192.0.2.50", Dst: "255.255.255.255", EthDst: pcapgen.Broadcast, Payload: make([]byte, 56)})
	}
}

// genIPv6MulticastPing: "ping -6 ff02::1%eth0" three times (hop limit 1,
// as for any link-local multicast); four hosts answer each.
func genIPv6MulticastPing(w *pcapgen.Writer) {
	w.Step = 300 * time.Millisecond
	for range 3 {
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "fe80::1", Dst: "ff02::1", TTL: 1, EthDst: net.HardwareAddr{0x33, 0x33, 0, 0, 0, 1}, Payload: make([]byte, 56)})
		for h := range 4 {
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: fmt.Sprintf("fe80::%d", 10+h), Dst: "fe80::1", ICMP: &[2]uint8{129, 0}, Payload: make([]byte, 56)})
		}
	}
}

// genTraceroute: "traceroute -q 3 8.8.8.8" from 10.0.0.5: UDP probes to
// ports 33434 and up with TTL 1-8, three per hop. Hops 1-7 answer ICMP
// Time Exceeded (quoting the probe); the target answers port unreachable.
func genTraceroute(w *pcapgen.Writer) {
	w.Step = 20 * time.Millisecond
	port := uint16(33434)
	for ttl := uint8(1); ttl <= 8; ttl++ {
		for range 3 {
			probe := pcapgen.Pkt{Proto: "udp", Src: "10.0.0.5", Dst: "8.8.8.8", Sport: 45000, Dport: port, TTL: ttl, Payload: make([]byte, 32)}
			port++
			w.Add(probe)
			if ttl == 8 {
				w.Add(pcapgen.Pkt{Proto: "icmp", Src: "8.8.8.8", Dst: "10.0.0.5", Unreach: &probe, TTL: 120})
				continue
			}
			quote := probe
			quote.TTL = 1 // the probe as the router saw it
			inner := quote.Bytes(nopTB{})[14:]
			router := "10.0.0.1"
			if ttl > 1 {
				router = fmt.Sprintf("100.64.%d.1", ttl)
			}
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: router, Dst: "10.0.0.5", ICMP: &[2]uint8{11, 0}, TTL: 255 - ttl + 1, Payload: inner[:28]})
		}
	}
}

// ttlFlow writes n UDP packets from src to 192.0.2.10:53 with TTL ttl.
func ttlFlow(w *pcapgen.Writer, src string, ttl uint8, n int) {
	for i := range n {
		w.Add(pcapgen.Pkt{Proto: "udp", Src: src, Dst: "192.0.2.10", Sport: 40000, Dport: 53, TTL: ttl, Payload: pcapgen.DNSQuery(uint16(i), "example.test", 1)})
	}
}

// genTTLSpoofedSource: 198.51.100.20 (14 hops away: TTL 50 from 64)
// sends 20 queries over 20s. Then 10 SYNs claiming to be from it arrive
// with TTL 120 (8 hops from 128): a spoofer on another path. The server
// answers the SYNs; nothing completes.
func genTTLSpoofedSource(w *pcapgen.Writer) {
	w.Step = time.Second
	ttlFlow(w, "198.51.100.20", 50, 20)
	w.Step = 200 * time.Millisecond
	for i := range 10 {
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: "198.51.100.20", Dst: "192.0.2.10", Sport: 30000 + uint16(i), Dport: 80, Flags: "S", Seq: 1000, TTL: 120})
		w.Add(pcapgen.Pkt{Proto: "tcp", Src: "192.0.2.10", Dst: "198.51.100.20", Sport: 80, Dport: 30000 + uint16(i), Flags: "SA", Seq: 5000, Ack: 1001})
	}
}

// genTTLNATMixedOS: a NAT address (198.51.100.30, 14 hops away) with a
// Linux host (initial TTL 64, arriving 50) and a Windows host (128,
// arriving 114) behind it, interleaved for 60 packets.
func genTTLNATMixedOS(w *pcapgen.Writer) {
	w.Step = 500 * time.Millisecond
	for range 30 {
		ttlFlow(w, "198.51.100.30", 50, 1)
		ttlFlow(w, "198.51.100.30", 114, 1)
	}
}

// genTTLRouteChangeSingle: 30 packets from 198.51.100.40 at TTL 50, one
// at TTL 45 (a transient detour), then 30 more at TTL 50.
func genTTLRouteChangeSingle(w *pcapgen.Writer) {
	w.Step = 500 * time.Millisecond
	ttlFlow(w, "198.51.100.40", 50, 30)
	ttlFlow(w, "198.51.100.40", 45, 1)
	ttlFlow(w, "198.51.100.40", 50, 30)
}

// udpDatagram returns an IP payload: a UDP header to port 9 and zeros,
// n bytes in all (the checksum is left zero, "none").
func udpDatagram(n int) []byte {
	b := make([]byte, n)
	binary.BigEndian.PutUint16(b[0:], 40000)
	binary.BigEndian.PutUint16(b[2:], 9)
	binary.BigEndian.PutUint16(b[4:], uint16(n))
	return b
}

// genTeardropOverlap: three teardrop datagrams from 203.0.113.70: a 1480
// byte first fragment, then a final fragment at offset 800 lying inside
// it.
func genTeardropOverlap(w *pcapgen.Writer) {
	w.Step = 10 * time.Millisecond
	for i := range 3 {
		id := uint32(0x1000 + i)
		w.AddFrag(pcapgen.Frag{Src: "203.0.113.70", Dst: "192.0.2.10", ID: id, Proto: 17, MF: true, Data: udpDatagram(1480)})
		w.AddFrag(pcapgen.Frag{Src: "203.0.113.70", Dst: "192.0.2.10", ID: id, Proto: 17, Offset: 800, Data: make([]byte, 200)})
	}
}

// genFragmentExactDuplicate: four 3000-byte UDP datagrams fragmented at
// MTU 1500 by 10.0.0.60, every fragment delivered twice (a duplicating
// link), the second copy of the first datagram after its last fragment.
func genFragmentExactDuplicate(w *pcapgen.Writer) {
	w.Step = time.Millisecond
	for i := range 4 {
		p := pcapgen.Pkt{Proto: "udp", Src: "10.0.0.60", Dst: "192.0.2.10", Sport: 5000, Dport: 9, Payload: make([]byte, 2972)}
		frags := pcapgen.Fragment(nopTB{}, p, uint32(0x2000+i), 1500)
		for _, f := range frags {
			w.AddFrag(f)
			w.AddFrag(f)
		}
		w.AddFrag(frags[0])
	}
}

// genTinyFirstFragment: "nmap -sS -f" from 203.0.113.80 against ports 22,
// 80 and 443: each 20-byte TCP SYN header is split into fragments of 8,
// 8 and 4 bytes.
func genTinyFirstFragment(w *pcapgen.Writer) {
	w.Step = 5 * time.Millisecond
	for i, port := range []uint16{22, 80, 443} {
		syn := pcapgen.Pkt{Proto: "tcp", Src: "203.0.113.80", Dst: "192.0.2.10", Sport: 61000, Dport: port, Flags: "S", Seq: 77}
		ip := syn.Bytes(nopTB{})[14:]
		hdr := ip[20:binary.BigEndian.Uint16(ip[2:])] // without Ethernet padding
		id := uint32(0x3000 + i)
		for off := 0; off < len(hdr); off += 8 {
			end := min(off+8, len(hdr))
			w.AddFrag(pcapgen.Frag{Src: syn.Src, Dst: syn.Dst, ID: id, Proto: 6, Offset: off, MF: end < len(hdr), Data: hdr[off:end]})
		}
	}
}

// genTinyIPv6FirstFragment: two IPv6 datagrams from 2001:db8:bad::1 whose
// 2048-byte Destination Options header does not fit in the 1232-byte first
// fragment, so the UDP header is only in the second (RFC 7112 forbids
// this; it hides the ports from filters).
func genTinyIPv6FirstFragment(w *pcapgen.Writer) {
	w.Step = 10 * time.Millisecond
	payload := make([]byte, 2048+8+100)
	payload[0], payload[1] = 17, 255 // next header UDP, (255+1)*8 bytes; the rest is Pad1
	binary.BigEndian.PutUint16(payload[2048:], 40000)
	binary.BigEndian.PutUint16(payload[2050:], 53)
	binary.BigEndian.PutUint16(payload[2052:], 108)
	for i := range 2 {
		id := uint32(0x4000 + i)
		w.AddFrag(pcapgen.Frag{Src: "2001:db8:bad::1", Dst: "2001:db8::10", ID: id, Proto: 60, MF: true, Data: payload[:1232]})
		w.AddFrag(pcapgen.Frag{Src: "2001:db8:bad::1", Dst: "2001:db8::10", ID: id, Proto: 60, Offset: 1232, Data: payload[1232:]})
	}
}

// genPingOfDeath: 203.0.113.90 sends an Echo Request in 45 fragments of
// 1480 bytes; the last starts at 65120 and ends at 66600, past 65535.
func genPingOfDeath(w *pcapgen.Writer) {
	w.Step = time.Millisecond
	data := make([]byte, 45*1480)
	data[0] = 8 // Echo Request; the checksum is not computed
	for i := range 45 {
		w.AddFrag(pcapgen.Frag{Src: "203.0.113.90", Dst: "192.0.2.10", ID: 0x5000, Proto: 1, Offset: i * 1480, MF: i < 44, Data: data[i*1480 : (i+1)*1480]})
	}
}

// genFragmentFlood: 203.0.113.66 sends the first fragments only of 60 UDP
// datagrams in 0.6s; they expire incomplete 30s later. A client's traffic
// 40s later moves the clock past the expiry.
func genFragmentFlood(w *pcapgen.Writer) {
	w.Step = 10 * time.Millisecond
	for i := range 60 {
		w.AddFrag(pcapgen.Frag{Src: "203.0.113.66", Dst: "192.0.2.10", ID: uint32(0x6000 + i), Proto: 17, MF: true, Data: udpDatagram(1480)})
	}
	w.Wait(40 * time.Second)
	w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.20", Dst: "192.0.2.53", Sport: 5353, Dport: 5353, Payload: []byte("tick")})
}

// genLegitLargePing: "ping -c 3 -s 8000" from 10.0.0.5 to 192.0.2.10 and
// to 2001:db8::10, at MTU 1500: each request and reply is an 8008-byte
// ICMP message in six fragments.
func genLegitLargePing(w *pcapgen.Writer) {
	w.Step = time.Millisecond
	id := uint32(0x7000)
	for _, pair := range [][2]string{{"10.0.0.5", "192.0.2.10"}, {"2001:db8::5", "2001:db8::10"}} {
		reply := uint8(0)
		if strings.Contains(pair[0], ":") {
			reply = 129
		}
		for range 3 {
			req := pcapgen.Pkt{Proto: "icmp", Src: pair[0], Dst: pair[1], Payload: make([]byte, 8000)}
			rep := pcapgen.Pkt{Proto: "icmp", Src: pair[1], Dst: pair[0], ICMP: &[2]uint8{reply, 0}, Payload: make([]byte, 8000)}
			for _, p := range []pcapgen.Pkt{req, rep} {
				for _, f := range pcapgen.Fragment(nopTB{}, p, id, 1500) {
					w.AddFrag(f)
				}
				id++
			}
			w.Wait(time.Second)
		}
	}
}

// nopTB lets generators serialize a frame before writing it.
type nopTB struct{ testing.TB }

func (nopTB) Helper()                   {}
func (nopTB) Fatal(args ...any)         { panic(fmt.Sprint(args...)) }
func (nopTB) Fatalf(f string, a ...any) { panic(fmt.Sprintf(f, a...)) }

// ARP scenarios run on the LAN 10.1.1.0/24: host 10.1.1.N has MAC
// pcapgen.MAC(N) (02:00:00:00:00:N in hex, e.g. 10.1.1.50 is ..:32), the
// gateway is 10.1.1.1, and the attacker's NIC is 02:00:00:00:00:66.

func lanIP(n int) string { return fmt.Sprintf("10.1.1.%d", n) }

const attackerMAC = 0x66

// arpAsk writes a broadcast request from host a for address target.
func arpAsk(w *pcapgen.Writer, a int, target string) {
	w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: lanIP(a), SenderMAC: pcapgen.MAC(uint16(a)), TargetIP: target})
}

// arpAnswer writes a reply to host a claiming address ip for mac.
func arpAnswer(w *pcapgen.Writer, ip string, mac net.HardwareAddr, a int) {
	w.AddARP(pcapgen.ARP{Op: pcapgen.ARPReply, SenderIP: ip, SenderMAC: mac, TargetIP: lanIP(a), TargetMAC: pcapgen.MAC(uint16(a))})
}

// arpExchange: host a asks for host b, which answers.
func arpExchange(w *pcapgen.Writer, a, b int) {
	arpAsk(w, a, lanIP(b))
	arpAnswer(w, lanIP(b), pcapgen.MAC(uint16(b)), a)
}

// arpProbeAnnounce writes what an RFC 5227 host does before using address
// n with MAC mac: three probes from 0.0.0.0 1s apart, then two gratuitous
// announcements 2s apart.
func arpProbeAnnounce(w *pcapgen.Writer, n int, mac net.HardwareAddr) {
	w.Step = time.Second
	for range 3 {
		w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: "0.0.0.0", SenderMAC: mac, TargetIP: lanIP(n)})
	}
	w.Step = 2 * time.Second
	for range 2 {
		w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: lanIP(n), SenderMAC: mac, TargetIP: lanIP(n)})
	}
	w.Step = time.Millisecond
}

// genARPNormalLAN: ten hosts (10.1.1.10-19) and the gateway over ten
// minutes. Every host resolves the gateway once a minute and the gateway
// resolves it back; hosts resolve each other now and then, and refresh
// entries with unicast requests (as Linux does for a STALE neighbour).
// Host 10.1.1.20 boots at 5 minutes: probes, a two-packet gratuitous
// announcement, then normal traffic.
func genARPNormalLAN(w *pcapgen.Writer) {
	for minute := range 10 {
		if minute == 5 {
			arpProbeAnnounce(w, 20, pcapgen.MAC(20))
			arpExchange(w, 20, 1)
		}
		for h := 10; h < 20; h++ {
			w.Step = 50 * time.Millisecond
			arpExchange(w, h, 1)
			arpExchange(w, 1, h)
			if h%3 == 0 {
				arpExchange(w, h, 10+(h-10+1+minute%9)%10) // never itself
			}
			// Unicast refresh of the gateway entry.
			w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: lanIP(h), SenderMAC: pcapgen.MAC(uint16(h)), TargetIP: lanIP(1),
				TargetMAC: pcapgen.MAC(1), EthDst: pcapgen.MAC(1)})
			arpAnswer(w, lanIP(1), pcapgen.MAC(1), h)
			w.Wait(5 * time.Second)
		}
		if minute >= 5 {
			arpExchange(w, 1, 20)
		}
	}
}

// genARPProbeZeroSender: DHCP clients checking addresses (RFC 5227).
// Client 02:..:30 probes 10.1.1.40, which host 10.1.1.40 defends with a
// reply to 0.0.0.0; the client then probes and announces 10.1.1.41. A
// second client probes twelve addresses in a row from one MAC.
func genARPProbeZeroSender(w *pcapgen.Writer) {
	arpExchange(w, 40, 1)
	w.Wait(10 * time.Second)
	c := pcapgen.MAC(30)
	w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: "0.0.0.0", SenderMAC: c, TargetIP: lanIP(40)})
	w.AddARP(pcapgen.ARP{Op: pcapgen.ARPReply, SenderIP: lanIP(40), SenderMAC: pcapgen.MAC(40), TargetIP: "0.0.0.0", TargetMAC: c})
	w.Wait(2 * time.Second)
	arpProbeAnnounce(w, 41, c)
	w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: lanIP(41), SenderMAC: c, TargetIP: lanIP(1)})
	w.AddARP(pcapgen.ARP{Op: pcapgen.ARPReply, SenderIP: lanIP(1), SenderMAC: pcapgen.MAC(1), TargetIP: lanIP(41), TargetMAC: c})
	w.Wait(10 * time.Second)
	c2 := pcapgen.MAC(31)
	w.Step = 300 * time.Millisecond
	for i := range 12 {
		w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: "0.0.0.0", SenderMAC: c2, TargetIP: lanIP(100 + i)})
	}
}

// genARPDHCPReassign: 10.1.1.50 belongs to 02:..:50 for the first 50
// minutes; at one hour the DHCP server hands it to 02:..:51, which probes
// and announces it.
func genARPDHCPReassign(w *pcapgen.Writer) {
	for range 10 {
		arpExchange(w, 50, 1)
		arpExchange(w, 1, 50)
		w.Wait(5*time.Minute - 2*time.Millisecond)
	}
	w.Now = pcapgen.T0.Add(time.Hour - 3*time.Second) // the probes take 3s
	arpProbeAnnounce(w, 50, pcapgen.MAC(51))
	for range 5 {
		w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: lanIP(50), SenderMAC: pcapgen.MAC(51), TargetIP: lanIP(1)})
		arpAnswer(w, lanIP(1), pcapgen.MAC(1), 50)
		w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: lanIP(1), SenderMAC: pcapgen.MAC(1), TargetIP: lanIP(50)})
		w.AddARP(pcapgen.ARP{Op: pcapgen.ARPReply, SenderIP: lanIP(50), SenderMAC: pcapgen.MAC(51), TargetIP: lanIP(1), TargetMAC: pcapgen.MAC(1)})
		w.Wait(time.Minute)
	}
}

// genARPStaticViolation: the gateway (pinned by arpbind) answers
// normally; then the attacker sends one reply claiming the gateway.
func genARPStaticViolation(w *pcapgen.Writer) {
	for h := 10; h < 15; h++ {
		arpExchange(w, h, 1)
		w.Wait(time.Second)
	}
	arpAnswer(w, lanIP(1), pcapgen.MAC(attackerMAC), 10)
	w.Wait(time.Second)
	arpExchange(w, 11, 1)
}

// genARPFlipFlop: an arpspoof-style attacker tells 10.1.1.10 every 2s that
// the gateway is at its MAC. The victim, losing its traffic, asks for the
// gateway every 10s and the real gateway answers, so the victim's entry
// for 10.1.1.1 flips back and forth for 60s. Replies within 5s of the
// victim's request count as solicited.
func genARPFlipFlop(w *pcapgen.Writer) {
	arpExchange(w, 10, 1)
	start := w.Now.Add(time.Second)
	for i := range 30 {
		w.Now = start.Add(time.Duration(i) * 2 * time.Second)
		if i%5 == 0 {
			arpExchange(w, 10, 1)
		}
		w.Now = start.Add(time.Duration(i)*2*time.Second + time.Second)
		arpAnswer(w, lanIP(1), pcapgen.MAC(attackerMAC), 10)
	}
}

// genARPUnsolicitedReplies: an IDS started after the gateway was last
// heard, so the binding is new. The attacker claims the gateway with a
// reply to 10.1.1.10 every 3s for a minute; nobody asked. Other hosts
// resolve each other normally, and 10.1.1.20 announces itself once.
func genARPUnsolicitedReplies(w *pcapgen.Writer) {
	arpProbeAnnounce(w, 20, pcapgen.MAC(20))
	start := w.Now
	for i := range 20 {
		w.Now = start.Add(time.Duration(i) * 3 * time.Second)
		arpAnswer(w, lanIP(1), pcapgen.MAC(attackerMAC), 10)
		w.Now = w.Now.Add(time.Second)
		arpExchange(w, 11+i%5, 20)
	}
}

// genARPMultiIP: one MAC answers the requests for 20 addresses in 40s,
// so every reply is solicited: an attacker answering for the whole subnet
// (or, in arp_proxy_router_passed, a proxy-ARP router).
func genARPMultiIP(prefix string, mac net.HardwareAddr) func(w *pcapgen.Writer) {
	return func(w *pcapgen.Writer) {
		for i := range 20 {
			target := fmt.Sprintf("%s.%d", prefix, 100+i)
			arpAsk(w, 10+i%5, target)
			arpAnswer(w, target, mac, 10+i%5)
			w.Wait(2 * time.Second)
		}
	}
}

// genARPEthMismatch: frames sent from the attacker's NIC (Ethernet source
// 02:..:66) whose ARP sender MAC is 10.1.1.30's real MAC, answering
// requests for 10.1.1.30 three times.
func genARPEthMismatch(w *pcapgen.Writer) {
	arpExchange(w, 10, 30)
	for range 3 {
		w.Wait(5 * time.Second)
		arpAsk(w, 10, lanIP(30))
		w.AddARP(pcapgen.ARP{Op: pcapgen.ARPReply, SenderIP: lanIP(30), SenderMAC: pcapgen.MAC(30), EthSrc: pcapgen.MAC(attackerMAC),
			TargetIP: lanIP(10), TargetMAC: pcapgen.MAC(10)})
	}
}

// genARPInvalidSenderMAC: requests whose sender MAC is broadcast (from
// 10.1.1.40), IPv4 multicast (10.1.1.41) and zero (10.1.1.42), among
// normal traffic. The frames carry the same bogus MAC as source.
func genARPInvalidSenderMAC(w *pcapgen.Writer) {
	arpExchange(w, 10, 1)
	for i, mac := range []net.HardwareAddr{pcapgen.Broadcast, {0x01, 0x00, 0x5e, 0, 0, 1}, pcapgen.ZeroMAC} {
		w.Wait(time.Second)
		w.AddARP(pcapgen.ARP{Op: pcapgen.ARPRequest, SenderIP: lanIP(40 + i), SenderMAC: mac, TargetIP: lanIP(1)})
	}
	arpExchange(w, 11, 1)
}

// ---------------------------------------------------------------------
// UDP flood, ICMP flood and ICMP tunnel scenarios. The udp_flood rules
// fire at 10000 packets (or 100000000 bytes) in 5s with at most 2%
// replies; the icmp_flood rules at 1000 Echo Requests or errors, or 100
// unsolicited Echo Replies, in 5s; icmp_tunnel at 10 non-standard echo
// payloads in 60s.

// linuxPing returns the payload of "ping -s n" on Linux: a 16-byte
// timestamp (made from seq, so it changes), then bytes counting up from
// 0x10.
func linuxPing(n int, seq uint16) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i)
	}
	if n >= 16 {
		binary.BigEndian.PutUint64(b, 0x66f5_0000_0000_0000|uint64(seq))
		binary.BigEndian.PutUint64(b[8:], 0x000a_8000+uint64(seq)*997)
	}
	return b
}

// windowsPing returns the payload of "ping -l n" on Windows.
func windowsPing(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 'a' + byte(i%23)
	}
	return b
}

// echoPair writes an Echo Request from src to dst and, if answered, its
// Echo Reply (same identifier, sequence number and payload).
func echoPair(w *pcapgen.Writer, src, dst string, id, seq uint16, payload []byte, answered bool) {
	reply := uint8(0)
	if strings.Contains(src, ":") {
		reply = 129
	}
	w.Add(pcapgen.Pkt{Proto: "icmp", Src: src, Dst: dst, Echo: &[2]uint16{id, seq}, Payload: payload})
	if answered {
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: dst, Dst: src, ICMP: &[2]uint8{reply, 0}, Echo: &[2]uint16{id, seq}, Payload: payload})
	}
}

// genUDPFloodSingleSource: 203.0.113.50:40000 sends 12000 64-byte UDP
// datagrams to 192.0.2.10:9999 in 3s. The port is open (a service that
// never answers), so nothing comes back.
func genUDPFloodSingleSource(w *pcapgen.Writer) {
	w.Step = 250 * time.Microsecond
	for range 12000 {
		w.Add(pcapgen.Pkt{Proto: "udp", Src: genScanner, Dst: genTarget, Sport: 40000, Dport: 9999, Payload: make([]byte, 64)})
	}
}

// genUDPFloodSpoofed: 12000 UDP datagrams to 192.0.2.10:80 in 3s, each
// from its own spoofed source in 198.18.0.0/15 and a random source port.
func genUDPFloodSpoofed(w *pcapgen.Writer) {
	w.Step = 250 * time.Microsecond
	rng := rand.New(rand.NewPCG(11, 0))
	for i := range 12000 {
		src := fmt.Sprintf("198.18.%d.%d", i>>8, i&0xff)
		w.Add(pcapgen.Pkt{Proto: "udp", Src: src, Dst: genTarget, Sport: uint16(1024 + rng.IntN(64000)), Dport: 80, Payload: make([]byte, 32)})
	}
}

// genUDPFloodBytes: "iperf -u -l 60000" on lo: 1800 datagrams of 60000
// bytes from 127.0.0.1:40000 to 127.0.0.1:9000 in 3.6s (lo's MTU is
// 65536, so none is fragmented). 1800 packets are far below the packet
// threshold; 108 MB is above the byte threshold. The capture is taken
// with a 128-byte snaplen, as the byte count comes from the UDP header.
func genUDPFloodBytes(w *pcapgen.Writer) {
	w.Step = 2 * time.Millisecond
	w.Snap = 128
	z := pcapgen.ZeroMAC
	payload := make([]byte, 60000)
	for range 1800 {
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "127.0.0.1", Dst: "127.0.0.1", Sport: 40000, Dport: 9000, Payload: payload, EthSrc: z, EthDst: z})
	}
}

// genQUICDownload: 10.0.0.5 downloads over QUIC from 203.0.113.80:443:
// 15000 1200-byte packets in 4s (3750 a second, 36 Mbit/s), and the
// client acknowledges every 15th, about 7% replies.
func genQUICDownload(w *pcapgen.Writer) {
	const client, server = "10.0.0.5", "203.0.113.80"
	w.Step = 250 * time.Microsecond
	w.Add(pcapgen.Pkt{Proto: "udp", Src: client, Dst: server, Sport: 51000, Dport: 443, Payload: make([]byte, 1200)}) // Initial
	w.Add(pcapgen.Pkt{Proto: "udp", Src: server, Dst: client, Sport: 443, Dport: 51000, Payload: make([]byte, 1200)})
	w.Add(pcapgen.Pkt{Proto: "udp", Src: client, Dst: server, Sport: 51000, Dport: 443, Payload: make([]byte, 60)})
	for i := range 15000 {
		w.Add(pcapgen.Pkt{Proto: "udp", Src: server, Dst: client, Sport: 443, Dport: 51000, Payload: make([]byte, 1200)})
		if i%15 == 14 {
			w.Add(pcapgen.Pkt{Proto: "udp", Src: client, Dst: server, Sport: 51000, Dport: 443, Payload: make([]byte, 40)})
		}
	}
}

// genVoIPCall: 10 s of a video call between 10.0.0.5:50000 and the
// conferencing server 198.51.100.30:3478. The server forwards the other
// participants' audio and video, 2200 packets a second; the client sends
// its own, 400 a second (15% replies).
func genVoIPCall(w *pcapgen.Writer) {
	const client, server = "10.0.0.5", "198.51.100.30"
	w.Step = 0
	for ms := range 10000 {
		w.Now = pcapgen.T0.Add(time.Duration(ms) * time.Millisecond)
		n := 2
		if ms%5 == 0 {
			n = 4 // 2200 a second in all
		}
		if ms%10 == 0 {
			n = 3
		}
		for range n {
			w.Add(pcapgen.Pkt{Proto: "udp", Src: server, Dst: client, Sport: 3478, Dport: 50000, Payload: make([]byte, 900)})
		}
		if ms%5 < 2 {
			w.Add(pcapgen.Pkt{Proto: "udp", Src: client, Dst: server, Sport: 50000, Dport: 3478, Payload: make([]byte, 700)})
		}
	}
}

// genUDPFloodToClosedPort: 12000 datagrams from 203.0.113.50:40000 to
// the closed port 192.0.2.10:7777 in 3s. The target answers ICMP port
// unreachable, rate limited to one per hundred datagrams.
func genUDPFloodToClosedPort(w *pcapgen.Writer) {
	w.Step = 250 * time.Microsecond
	for i := range 12000 {
		probe := pcapgen.Pkt{Proto: "udp", Src: genScanner, Dst: genTarget, Sport: 40000, Dport: 7777, Payload: make([]byte, 64)}
		w.Add(probe)
		if i%100 == 0 {
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: genTarget, Dst: genScanner, Unreach: &probe})
		}
	}
}

// genICMPEchoFlood: "ping -f -c 3000" from 203.0.113.50 to 192.0.2.10:
// 3000 standard 56-byte Echo Requests 1 ms apart, every one answered.
func genICMPEchoFlood(w *pcapgen.Writer) {
	w.Step = 500 * time.Microsecond
	for i := range 3000 {
		seq := uint16(i + 1)
		echoPair(w, genScanner, genTarget, 0x4d2, seq, linuxPing(56, seq), true)
	}
}

// genICMPMonitoringPings: a monitoring server (10.0.0.2) pings 30 hosts
// (10.0.1.1-30) once a second each for a minute; all answer.
func genICMPMonitoringPings(w *pcapgen.Writer) {
	w.Step = time.Millisecond
	for s := range 60 {
		w.Now = pcapgen.T0.Add(time.Duration(s) * time.Second)
		seq := uint16(s + 1)
		for h := range 30 {
			echoPair(w, "10.0.0.2", fmt.Sprintf("10.0.1.%d", h+1), uint16(0x100+h), seq, linuxPing(56, seq), true)
		}
	}
}

// genSmurfVictim: 192.0.2.50 receives 600 Echo Replies in 3s from 150
// hosts it never pinged: the attacker sent Echo Requests with 192.0.2.50
// as spoofed source elsewhere, and the replies all land here.
func genSmurfVictim(w *pcapgen.Writer) {
	w.Step = 5 * time.Millisecond
	for i := range 600 {
		src := fmt.Sprintf("198.51.100.%d", 1+i%150)
		seq := uint16(i/150 + 1)
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: src, Dst: "192.0.2.50", ICMP: &[2]uint8{0, 0}, Echo: &[2]uint16{0x5151, seq}, Payload: linuxPing(56, seq)})
	}
}

// genNormalPingReplies: 10.0.0.5 runs "ping -i 0.01 -c 500" to
// 192.0.2.10 (500 replies in 5s, some duplicated or up to 8s late) and
// "ping -6 -c 20" to 2001:db8::10.
func genNormalPingReplies(w *pcapgen.Writer) {
	w.Step = 5 * time.Millisecond
	for i := range 500 {
		seq := uint16(i + 1)
		p := linuxPing(56, seq)
		switch {
		case i%50 == 7: // the reply comes 8s later, after the others
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: "10.0.0.5", Dst: genTarget, Echo: &[2]uint16{0x77, seq}, Payload: p})
			defer func() {
				w.Add(pcapgen.Pkt{Proto: "icmp", Src: genTarget, Dst: "10.0.0.5", ICMP: &[2]uint8{0, 0}, Echo: &[2]uint16{0x77, seq}, Payload: p})
			}()
		case i%50 == 9: // DUP!
			echoPair(w, "10.0.0.5", genTarget, 0x77, seq, p, true)
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: genTarget, Dst: "10.0.0.5", ICMP: &[2]uint8{0, 0}, Echo: &[2]uint16{0x77, seq}, Payload: p})
		default:
			echoPair(w, "10.0.0.5", genTarget, 0x77, seq, p, true)
		}
	}
	w.Wait(3 * time.Second) // the late replies arrive 8s after their requests
	w.Step = time.Second
	for i := range 20 {
		seq := uint16(i + 1)
		echoPair(w, "2001:db8::5", "2001:db8::10", 0x78, seq, linuxPing(56, seq), true)
	}
}

// genICMPErrorFlood: a BlackNurse attack: 203.0.113.50 sends 2000 ICMP
// port unreachables in 2s to the firewall 192.0.2.10, quoting datagrams
// the firewall never sent (so they are not scan answers either).
func genICMPErrorFlood(w *pcapgen.Writer) {
	w.Step = time.Millisecond
	for i := range 2000 {
		quoted := pcapgen.Pkt{Proto: "udp", Src: "198.51.100.77", Dst: "198.51.100.1", Sport: 5000, Dport: uint16(1 + i%1000)}
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: genScanner, Dst: genTarget, Unreach: &quoted})
	}
}

// tunnelExchange is a remote shell over ICMP (icmpsh-style) between
// client 10.0.0.5 and server 198.51.100.20: each command goes out in an
// Echo Request and its output comes back in the Reply.
var tunnelExchange = [][2]string{
	{"id", "uid=0(root) gid=0(root) groups=0(root)\n"},
	{"hostname", "db-prod-02\n"},
	{"uname -a", "Linux db-prod-02 6.1.0-18-amd64 #1 SMP Debian 6.1.76-1 x86_64 GNU/Linux\n"},
	{"ls /home", "alice\nbob\nbackup\n"},
	{"cat /etc/hostname", "db-prod-02\n"},
	{"ls -la /var/backups", "total 8\ndrwxr-xr-x 2 root root 4096 .\ndrwxr-xr-x 12 root root 4096 ..\n"},
	{"whoami", "root\n"},
	{"pwd", "/root\n"},
}

// genICMPTunnelVariedSizes: tunnelExchange, one command every 2s. The
// payloads are text (low entropy) but come in many sizes.
func genICMPTunnelVariedSizes(w *pcapgen.Writer) {
	w.Step = 50 * time.Millisecond
	for i, ex := range tunnelExchange {
		seq := uint16(i + 1)
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "10.0.0.5", Dst: "198.51.100.20", Echo: &[2]uint16{0x1337, seq}, Payload: []byte(ex[0])})
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "198.51.100.20", Dst: "10.0.0.5", ICMP: &[2]uint8{0, 0}, Echo: &[2]uint16{0x1337, seq}, Payload: []byte(ex[1])})
		w.Wait(2 * time.Second)
	}
}

// genICMPTunnelHighEntropy: an encrypted tunnel (hans-style) padding
// every packet to 1024 bytes: 15 Echo Requests and Replies, one pair a
// second, all of the same size but random-looking.
func genICMPTunnelHighEntropy(w *pcapgen.Writer) {
	w.Step = 30 * time.Millisecond
	rng := rand.New(rand.NewPCG(7, 7))
	random := func() []byte {
		b := make([]byte, 1024)
		for i := range b {
			b[i] = byte(rng.IntN(256))
		}
		return b
	}
	for i := range 15 {
		seq := uint16(i + 1)
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "10.0.0.5", Dst: "198.51.100.21", Echo: &[2]uint16{0x2222, seq}, Payload: random()})
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "198.51.100.21", Dst: "10.0.0.5", ICMP: &[2]uint8{0, 0}, Echo: &[2]uint16{0x2222, seq}, Payload: random()})
		w.Wait(time.Second)
	}
}

// genLinuxPingStandard: Linux ping from 10.0.0.5: "ping -c 20" to
// 8.8.8.8, then "-s 100", "-s 1000", "-s 8" (timestamp only) and "-s 4"
// (too short for a timestamp) to 192.0.2.10, 5 each, all answered, and
// "ping -6 -s 200" to 2001:db8::10. Many sizes, all standard.
func genLinuxPingStandard(w *pcapgen.Writer) {
	w.Step = 20 * time.Millisecond
	seq := uint16(0)
	ping := func(dst string, size, n int) {
		for range n {
			seq++
			echoPair(w, "10.0.0.5", dst, 0x3a01, seq, linuxPing(size, seq), true)
			w.Wait(time.Second)
		}
	}
	ping("8.8.8.8", 56, 20)
	for _, size := range []int{100, 1000, 8, 4} {
		ping(genTarget, size, 5)
	}
	for range 5 {
		seq++
		echoPair(w, "2001:db8::5", "2001:db8::10", 0x3a02, seq, linuxPing(200, seq), true)
		w.Wait(time.Second)
	}
}

// genWindowsPingStandard: Windows ping from 10.0.0.7 (TTL 128): "ping -n
// 20" (32 bytes) to 8.8.8.8, then "-l 500" and "-l 1472" to 192.0.2.10,
// 5 each, and "ping -l 0".
func genWindowsPingStandard(w *pcapgen.Writer) {
	w.Step = 20 * time.Millisecond
	seq := uint16(0)
	ping := func(dst string, size, n int) {
		for range n {
			seq++
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: "10.0.0.7", Dst: dst, TTL: 128, Echo: &[2]uint16{1, seq}, Payload: windowsPing(size)})
			w.Add(pcapgen.Pkt{Proto: "icmp", Src: dst, Dst: "10.0.0.7", ICMP: &[2]uint8{0, 0}, TTL: 117, Echo: &[2]uint16{1, seq}, Payload: windowsPing(size)})
			w.Wait(time.Second)
		}
	}
	ping("8.8.8.8", 32, 20)
	ping(genTarget, 500, 5)
	ping(genTarget, 1472, 5)
	ping(genTarget, 0, 5)
}

// genLargeStandardPing: "ping -c 3 -s 4000 127.0.0.1" on lo (MTU 65536,
// so each request is one frame) and "ping -c 3 -s 8000" between two
// hosts on a jumbo-frame LAN (MTU 9000); both standard Linux payloads.
// "ping -c 3 -s 1472" fills a 1500-byte frame exactly and is not
// oversized.
func genLargeStandardPing(w *pcapgen.Writer) {
	w.Step = time.Millisecond
	z := pcapgen.ZeroMAC
	for i := range 3 {
		seq := uint16(i + 1)
		p := linuxPing(4000, seq)
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "127.0.0.1", Dst: "127.0.0.1", Echo: &[2]uint16{0x10, seq}, Payload: p, EthSrc: z, EthDst: z})
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "127.0.0.1", Dst: "127.0.0.1", ICMP: &[2]uint8{0, 0}, Echo: &[2]uint16{0x10, seq}, Payload: p, EthSrc: z, EthDst: z})
		echoPair(w, "10.0.0.5", "10.0.0.9", 0x11, seq, linuxPing(8000, seq), true)
		echoPair(w, "10.0.0.5", genTarget, 0x12, seq, linuxPing(1472, seq), true)
		w.Wait(time.Second)
	}
}

// genReflectionNTPSSDP: 192.0.2.50 is the victim of a reflection attack:
// 60 NTP servers answer spoofed monlist requests (468-byte mode 7
// responses from port 123) and 40 hosts answer spoofed SSDP M-SEARCHes
// (from port 1900), 3000 datagrams in 3s. Before it, 10.0.0.5 syncs
// with four NTP servers, which must not look like reflection.
func genReflectionNTPSSDP(w *pcapgen.Writer) {
	w.Step = 10 * time.Millisecond
	for i := range 4 {
		srv := fmt.Sprintf("198.51.100.%d", 200+i)
		w.Add(pcapgen.Pkt{Proto: "udp", Src: "10.0.0.5", Dst: srv, Sport: 123, Dport: 123, Payload: make([]byte, 48)})
		w.Add(pcapgen.Pkt{Proto: "udp", Src: srv, Dst: "10.0.0.5", Sport: 123, Dport: 123, Payload: make([]byte, 48)})
	}
	w.Wait(10 * time.Second)
	w.Step = time.Millisecond
	ssdp := []byte("HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nST: upnp:rootdevice\r\nUSN: uuid:0000::upnp:rootdevice\r\nLOCATION: http://192.168.1.1:1900/rootDesc.xml\r\nSERVER: Linux UPnP/1.0\r\n\r\n")
	for i := range 3000 {
		if i%5 < 3 {
			w.Add(pcapgen.Pkt{Proto: "udp", Src: fmt.Sprintf("203.0.113.%d", 1+i%60), Dst: "192.0.2.50", Sport: 123, Dport: 44321, Payload: make([]byte, 468)})
		} else {
			w.Add(pcapgen.Pkt{Proto: "udp", Src: fmt.Sprintf("198.51.100.%d", 1+i%40), Dst: "192.0.2.50", Sport: 1900, Dport: 44321, Payload: ssdp})
		}
	}
}

// genMLDFromUnspecified: a host joining multicast groups before it has an
// address: MLDv2 reports (ICMPv6 143) from :: to ff02::16 with hop limit
// 1, and a DAD Neighbor Solicitation from :: (hop limit 255). :: is not
// in $HOME_NET, so before sid 1000409 rev 2 the reports fired low TTL.
// The Hop-by-Hop Router Alert option real reports carry is left out.
func genMLDFromUnspecified(w *pcapgen.Writer) {
	w.Step = 200 * time.Millisecond
	mldDst := net.HardwareAddr{0x33, 0x33, 0, 0, 0, 0x16}
	report := []byte{0, 0, 0, 1, 4, 0, 0, 0, 0xff, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfb}
	for range 3 {
		w.Add(pcapgen.Pkt{Proto: "icmp", Src: "::", Dst: "ff02::16", TTL: 1, ICMP: &[2]uint8{143, 0}, EthDst: mldDst, Payload: report})
	}
	ns := append([]byte{0, 0, 0, 0}, net.ParseIP("fe80::5")...)
	w.Add(pcapgen.Pkt{Proto: "icmp", Src: "::", Dst: "ff02::1:ff00:5", TTL: 255, ICMP: &[2]uint8{135, 0}, EthDst: net.HardwareAddr{0x33, 0x33, 0xff, 0, 0, 5}, Payload: ns})
}
