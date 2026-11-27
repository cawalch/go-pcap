package pcap_test

import (
	"fmt"
	"os"

	pcap "github.com/cawalch/go-pcap"
)

func ExampleCapture_SMB2EvidenceFromReaderAt() {
	source, err := os.Open("testdata/framing/smb-evidence.pcapng")
	if err != nil {
		panic(err)
	}
	defer func() { _ = source.Close() }()
	info, err := source.Stat()
	if err != nil {
		panic(err)
	}
	capture, err := pcap.NewFromReaderAt(source, info.Size())
	if err != nil {
		panic(err)
	}
	rows, err := capture.SMB2EvidenceFromReaderAt(source)
	if err != nil {
		panic(err)
	}
	if len(rows) == 0 {
		return
	}
	row := rows[0]
	fmt.Printf("opening packet %d: message %d share %s\n",
		row.OpeningPacket, row.Message.MessageID, row.Message.ShareName)
	// Read the packet record from the same original capture.
	for packet, err := range capture.PacketSeqFromReaderAt(source) {
		if err != nil {
			panic(err)
		}
		if packet.Index == row.PacketIndex {
			fmt.Printf("command starts in frame %d at recovered stream offset %d\n", packet.Index+1, row.StreamOffset)
			break
		}
	}
	// Output:
	// opening packet 0: message 42 share \\server\share
	// command starts in frame 3 at recovered stream offset 4
}
