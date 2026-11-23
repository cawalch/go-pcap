package pcap

// WebRecords contains the results of TLS, HTTP/1 and HTTP/2 analysis.
// Each slice follows the ordering of its corresponding Capture method.
type WebRecords struct {
	TLS   []TLSRecord
	HTTP  []HTTPRecord
	HTTP2 []HTTP2Record
}

// Web reassembles TCP once to produce the records returned by [Capture.TLS],
// [Capture.HTTP] and [Capture.HTTP2]. Embedded key logs enable inspection of
// supported encrypted streams. Each protocol retains its own scan limits.
// On error, Web returns an empty result.
func (c *Capture) Web(data []byte) (WebRecords, error) {
	streams, err := c.Streams(data)
	if err != nil || len(streams) == 0 {
		return WebRecords{}, err
	}
	keys, err := c.TLSKeyLog(nil)
	if err != nil {
		return WebRecords{}, err
	}
	var out WebRecords
	out.TLS, err = tlsRecordsFromStreams(streams, keys)
	if err != nil {
		return WebRecords{}, err
	}
	if err := scanHTTPStreams(streams, keys, &out.HTTP, &out.HTTP2); err != nil {
		return WebRecords{}, err
	}
	return out, nil
}

// scanHTTPStreams consumes the caller's reassembled streams. A nil destination
// skips that HTTP version. Process cleartext before decryption to preserve
// record order and charge both passes to the same per-protocol budgets.
func scanHTTPStreams(streams []TCPStream, keys *TLSKeyLog, http1 *[]HTTPRecord, http2 *[]HTTP2Record) error {
	decoded := httpDecodeBudget{remaining: MaxHTTPDecodedBodyBytesPerScan}
	remaining := MaxHTTP2DecodedHeaderBytes
	for i := range streams {
		inner, co, so := proxyStream(streams[i])
		if http1 != nil {
			if err := appendClearHTTP(&streams[i], &inner, co, so, http1, &decoded); err != nil {
				return err
			}
		}
		if http2 != nil {
			if err := appendHTTP2FromTCPStream(&inner, false, http2, &remaining); err != nil {
				return err
			}
		}
		streams[i] = inner
	}
	if keys != nil && len(keys.Entries) > 0 {
		decrypted := decryptTLSStreams(streams, keys)
		for i := range decrypted {
			if http1 != nil {
				if err := appendHTTPFromTCPStream(&decrypted[i], true, http1, &decoded, 0, 0); err != nil {
					return err
				}
			}
			if http2 != nil {
				if err := appendHTTP2FromTCPStream(&decrypted[i], true, http2, &remaining); err != nil {
					return err
				}
			}
		}
	}
	return nil
}
