// Command keyed-http1-export selects the first confirmed HTTP/1 transaction
// with the given request target using a capture's embedded TLS test keys.
// Redirect standard output to a PcapNG file.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/cawalch/go-pcap"
	"github.com/cawalch/go-pcap/examples/internal/captureinput"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: keyed-http1-export {capture.pcapng[.gz]|-} request-target > selected.pcapng")
		os.Exit(2)
	}
	if err := run(os.Args[1], os.Args[2], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path, target string, stdin io.Reader, out io.Writer) error {
	input, err := captureinput.Open(path, stdin)
	if err != nil {
		return err
	}
	defer func() { _ = input.Close() }()
	rows, err := input.Capture.KeyedHTTP1TransactionsFromReaderAt(input.File, nil)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.Request.Target == target && row.Pairing == pcap.HTTP1ResponseConfirmed {
			return input.Capture.ExtractKeyedHTTP1TransactionPCAPNGFromReaderAt(input.File, nil, out, row.ID)
		}
	}
	return fmt.Errorf("capture has no confirmed transaction for %q", target)
}
