module github.com/cawalch/go-pcap/benchmarks/gopacket

go 1.26.0

require (
	github.com/cawalch/go-pcap v0.0.0
	github.com/gopacket/gopacket v1.3.1
)

require (
	golang.org/x/net v0.28.0 // indirect
	golang.org/x/sys v0.24.0 // indirect
)

replace github.com/cawalch/go-pcap => ../..
