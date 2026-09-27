package main

// Pcap generators for testdata/scenarios. Each writes realistic traffic
// (correct sequence numbers, both directions) with pcapgen. Addresses come
// from the documentation ranges: 192.0.2.0/24 servers, 203.0.113.0/24
// attackers, 10.0.0.0/8 clients, 198.18.0.0/15 spoofed sources.

import (
	"encoding/binary"
	"fmt"
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
