// Command keyed-http1-export selects the first confirmed HTTP/1 transaction
// with the given request target using a capture's embedded TLS test keys.
// Redirect standard output to a PcapNG file.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/cawalch/go-pcap"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: keyed-http1-export capture.pcapng request-target > selected.pcapng")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path, target string, out io.Writer) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return err
	}
	c, err := pcap.NewFromReaderAt(f, info.Size())
	if err != nil {
		return err
	}
	rows, err := c.KeyedHTTP1TransactionsFromReaderAt(f, nil)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Request.Target == target && row.Pairing == pcap.HTTP1ResponseConfirmed {
			return c.ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(f, nil, out, row.ID)
		}
	}
	return fmt.Errorf("capture has no confirmed transaction for %q", target)
}
