// Tiny HTTPS origin server for the bench.
//
// Serves:
//   GET  /download/{N}                - streams N bytes of zeros (e.g. /download/1073741824)
//   PUT  /upload/{anything}           - drains the body, returns 200 with the byte count
//   GET  /healthz                     - returns 200 "ok"
//
// All other paths return 404. TLS cert/key paths and the listen address come
// from flags. HTTP/2 is enabled by default via Go's net/http.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
)

const zeroChunk = 64 * 1024

var zeroBuf = make([]byte, zeroChunk)

func main() {
	listen := flag.String("listen", "127.0.0.1:8443", "HTTPS listen address")
	certPath := flag.String("cert", "certs/cert.pem", "TLS cert chain")
	keyPath := flag.String("key", "certs/key.pem", "TLS private key")
	flag.Parse()

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/download/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "GET only", http.StatusMethodNotAllowed)
			return
		}
		sizeStr := strings.TrimPrefix(r.URL.Path, "/download/")
		size, err := strconv.ParseInt(sizeStr, 10, 64)
		if err != nil || size < 0 {
			http.Error(w, "bad size", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(size, 10))
		w.WriteHeader(http.StatusOK)
		var written int64
		for written < size {
			chunk := int64(len(zeroBuf))
			if remain := size - written; remain < chunk {
				chunk = remain
			}
			n, err := w.Write(zeroBuf[:chunk])
			written += int64(n)
			if err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/upload/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			http.Error(w, "PUT/POST only", http.StatusMethodNotAllowed)
			return
		}
		n, err := io.Copy(io.Discard, r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		_ = r.Body.Close()
		_, _ = fmt.Fprintf(w, "received %d bytes\n", n)
	})

	srv := &http.Server{
		Addr:    *listen,
		Handler: mux,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			NextProtos: []string{"h2", "http/1.1"},
		},
	}
	log.Printf("bench-origin listening on https://%s", *listen)
	if err := srv.ListenAndServeTLS(*certPath, *keyPath); err != nil {
		log.Fatalf("origin: %v", err)
	}
}
