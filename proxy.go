package pcap

import (
	"bytes"
	"encoding/binary"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// UnwrapProxyStream returns the inner byte slices and requested target of one
// successful explicit proxy handshake. The proxy type is "http-connect" or
// "socks5". Both returned slices borrow their respective input buffers.
// Unrecognized or incomplete exchanges return the original slices and false.
func UnwrapProxyStream(client, server []byte) (innerClient, innerServer []byte, proxyType string, targetHost string, targetPort uint16, unwrapped bool) {
	if bytes.HasPrefix(client, []byte("CONNECT ")) {
		clientLine, cEnd := proxyHTTPHeader(client)
		target, version, ok := strings.Cut(strings.TrimPrefix(clientLine, "CONNECT "), " ")
		sEnd := proxyConnectResponseEnd(server)
		if ok && (version == "HTTP/1.1" || version == "HTTP/1.0") && sEnd != 0 {
			host, port, err := net.SplitHostPort(target)
			n, parseErr := strconv.ParseUint(port, 10, 16)
			if err == nil && parseErr == nil && n != 0 && host != "" && !strings.ContainsAny(host, "/?#@") && strings.IndexFunc(host, func(r rune) bool { return r <= ' ' || r == 127 }) == -1 {
				return client[cEnd:], server[sEnd:], "http-connect", host, uint16(n), true
			}
		}
	}
	if len(client) >= 3 && client[0] == 5 && len(server) >= 2 && server[0] == 5 && server[1] == 0 {
		n := int(client[1])
		if n >= 1 && n <= 16 && 2+n <= len(client) && bytes.IndexByte(client[2:2+n], 0) >= 0 {
			request, reply := client[2+n:], server[2:]
			address, cEnd := socksAddress(request, 1)
			_, sEnd := socksAddress(reply, 0)
			if cEnd != 0 && sEnd != 0 {
				host := string(address)
				if request[3] != 3 {
					ip, _ := netip.AddrFromSlice(address)
					host = ip.String()
				}
				port := binary.BigEndian.Uint16(request[cEnd-2 : cEnd])
				if port != 0 {
					return request[cEnd:], reply[sEnd:], "socks5", host, port, true
				}
			}
		}
	}
	return client, server, "", "", 0, false
}

// proxyHTTPHeader reads the start line only after finding a complete header.
func proxyHTTPHeader(data []byte) (string, int) {
	end := bytes.Index(data[:min(len(data), 4096)], []byte("\r\n\r\n"))
	if end < 0 {
		return "", 0
	}
	line, _, _ := bytes.Cut(data[:end], []byte("\r\n"))
	return string(line), end + 4
}

// Include provisional responses in the same bounded handshake as the final 2xx.
func proxyConnectResponseEnd(data []byte) int {
	data = data[:min(len(data), 4096)]
	for off := 0; off < len(data); {
		line, n := proxyHTTPHeader(data[off:])
		proto, status, ok := strings.Cut(line, " ")
		code, _, _ := strings.Cut(status, " ")
		if !ok || (proto != "HTTP/1.0" && proto != "HTTP/1.1") || len(code) != 3 || code[1] < '0' || code[1] > '9' || code[2] < '0' || code[2] > '9' {
			break
		}
		off += n
		if code[0] == '2' {
			return off
		}
		if code[0] != '1' || code == "101" {
			break
		}
	}
	return 0
}

func socksAddress(message []byte, code byte) ([]byte, int) {
	if len(message) < 5 || message[0] != 5 || message[1] != code || message[2] != 0 {
		return nil, 0
	}
	offset, n := 4, 0
	switch message[3] {
	case 1:
		n = 4
	case 3:
		n = int(message[4])
		offset++
	case 4:
		n = 16
	default:
		return nil, 0
	}
	if n == 0 || len(message) < offset+n+2 {
		return nil, 0
	}
	return message[offset : offset+n], offset + n + 2
}

func (st *TCPStream) reverse() {
	st.Client, st.Server = st.Server, st.Client
	st.SrcAddr, st.DstAddr = st.DstAddr, st.SrcAddr
	st.SrcPort, st.DstPort = st.DstPort, st.SrcPort
}

// proxyStream orients a recognized tunnel to its request and retains the wire
// offsets of the inner payloads. It operates on a copy of the stream metadata.
func proxyStream(st TCPStream) (TCPStream, int, int) {
	client, server, _, _, _, ok := UnwrapProxyStream(st.Client.Data, st.Server.Data)
	if !ok {
		client, server, _, _, _, ok = UnwrapProxyStream(st.Server.Data, st.Client.Data)
		if !ok {
			return st, 0, 0
		}
		st.reverse()
	}
	co, so := len(st.Client.Data)-len(client), len(st.Server.Data)-len(server)
	st.Client.Data, st.Server.Data = client, server
	return st, co, so
}

// proxyStreams prepares owned reassembly results for cleartext inspection and
// TLS decryption. Each stream is unwrapped at most once.
func (c *Capture) proxyStreams(data []byte) ([]TCPStream, error) {
	streams, err := c.Streams(data)
	if err != nil {
		return nil, err
	}
	for i := range streams {
		streams[i], _, _ = proxyStream(streams[i])
	}
	return streams, nil
}
