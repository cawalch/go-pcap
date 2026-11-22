module github.com/cawalch/go-pcap/benchmarks/gopacket

go 1.26.0

require (
	github.com/cawalch/go-pcap v0.0.0
	github.com/gopacket/gopacket v1.7.7
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/cawalch/go-pcap => ../..
