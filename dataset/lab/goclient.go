// goclient.go: minimal Go net/http HTTPS client for the dataset lab.
// Usage: goclient URL COUNT
package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
)

func main() {
	url := os.Args[1]
	n, _ := strconv.Atoi(os.Args[2])
	for i := 0; i < n; i++ {
		// A fresh transport per request forces a fresh TLS handshake.
		client := &http.Client{Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		}}
		resp, err := client.Get(url)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			continue
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}
