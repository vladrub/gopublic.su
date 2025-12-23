package main

import (
	"bufio"
	"encoding/json"
	"gopublic/pkg/protocol"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/hashicorp/yamux"
)

// ServerAddr is set via ldflags during build. e.g. -X main.ServerAddr=example.com:4443
var ServerAddr = "localhost:4443"

func main() {
	log.Printf("Connecting to server at: %s", ServerAddr)

	// 1. Connect
	conn, err := net.Dial("tcp", ServerAddr)
	if err != nil {
		log.Fatalf("Failed to connect: %v", err)
	}
	defer conn.Close()

	// 2. Start Yamux Client
	session, err := yamux.Client(conn, nil)
	if err != nil {
		log.Fatalf("Failed to start yamux: %v", err)
	}

	// 3. Handshake (Stream 1)
	stream, err := session.Open()
	if err != nil {
		log.Fatalf("Failed to open handshake stream: %v", err)
	}

	// Auth
	authReq := protocol.AuthRequest{Token: "sk_live_12345"}
	json.NewEncoder(stream).Encode(authReq)

	// Tunnel
	tunnelReq := protocol.TunnelRequest{RequestedDomains: []string{"misty-river"}}
	json.NewEncoder(stream).Encode(tunnelReq)

	// Response
	var resp protocol.InitResponse
	json.NewDecoder(stream).Decode(&resp)
	if !resp.Success {
		log.Fatalf("Handshake failed: %s", resp.Error)
	}
	log.Printf("Handshake success! Bound: %v", resp.BoundDomains)
	stream.Close() // Handshake done

	// 4. Listen for incoming requests
	log.Println("Waiting for requests...")
	for {
		stream, err := session.Accept()
		if err != nil {
			log.Printf("Session ended: %v", err)
			return
		}
		go handleRequest(stream)
	}
}

func handleRequest(stream net.Conn) {
	defer stream.Close()
	// Read Request
	req, err := http.ReadRequest(bufio.NewReader(stream))
	if err != nil {
		log.Printf("Failed to read request: %v", err)
		return
	}
	log.Printf("Received Request: %s %s", req.Method, req.Host)

	// Write Response
	resp := http.Response{
		StatusCode: 200,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Body:       io.NopCloser(strings.NewReader("Hello from Mock Client!")),
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/plain")
	resp.ContentLength = int64(len("Hello from Mock Client!"))

	resp.Write(stream)
}
