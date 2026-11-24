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
	return c.scanWeb(data, nil)
}

// WebWithWebSockets returns the same ordered records as [Capture.Web] and
// [Capture.WebSockets], sharing TCP reassembly and application-data decryption.
// An error from either analysis discards both results.
func (c *Capture) WebWithWebSockets(data []byte) (WebRecords, []WebSocketRecord, error) {
	ws := webSocketScan{remaining: MaxTotalStreamBytes}
	web, err := c.scanWeb(data, &ws)
	if err != nil {
		return WebRecords{}, nil, err
	}
	return web, ws.records, nil
}

func (c *Capture) scanWeb(data []byte, ws *webSocketScan) (WebRecords, error) {
	var meta []streamMetadata
	streams, err := collectStreams(ipFrameSource{capture: c, data: data}, 0, &meta)
	if err != nil || (len(streams) == 0 && ws == nil) {
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
	if err := scanHTTPStreams(streams, meta, keys, &out.HTTP, &out.HTTP2, ws); err != nil {
		return WebRecords{}, err
	}
	return out, nil
}

// scanHTTPStreams consumes the caller's reassembled streams. A nil destination
// skips that HTTP version. Process cleartext before decryption to preserve
// record order and charge both passes to the same per-protocol budgets.
func scanHTTPStreams(streams []TCPStream, meta []streamMetadata, keys *TLSKeyLog, http1 *[]HTTPRecord, http2 *[]HTTP2Record, ws *webSocketScan) error {
	decoded := httpDecodeBudget{remaining: MaxHTTPDecodedBodyBytesPerScan}
	remaining := MaxHTTP2DecodedHeaderBytes
	for i := range streams {
		inner, co, so := proxyStream(streams[i])
		if http1 != nil {
			wire := streams[i]
			clearInner := inner
			if wire.Client.Anomalies.SequenceGap || wire.Server.Anomalies.SequenceGap {
				wire.Client.Data = wire.Client.Data[:meta[i].clientPrefix]
				wire.Server.Data = wire.Server.Data[:meta[i].serverPrefix]
				clearInner, co, so = proxyStream(wire)
			}
			if err := appendClearHTTP(&wire, &clearInner, co, so, http1, &decoded); err != nil {
				return err
			}
		}
		if http2 != nil {
			if err := appendHTTP2FromTCPStream(&inner, false, http2, &remaining); err != nil {
				return err
			}
		}
		if ws != nil {
			if err := ws.appendStream(inner, false); err != nil {
				return err
			}
		}
		streams[i] = inner
	}
	if keys != nil && len(keys.Entries) > 0 {
		decrypted := decryptTLSStreams(streams, keys)
		for i := range decrypted {
			if ws != nil {
				if err := ws.appendStream(decrypted[i], true); err != nil {
					return err
				}
			}
			if http1 != nil {
				if err := appendHTTPFromTCPStream(decrypted[i], true, http1, &decoded, 0, 0); err != nil {
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
