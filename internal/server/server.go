package server

import (
	"crypto/tls"
	"encoding/json"
	"gopublic/internal/storage"
	"gopublic/pkg/protocol"
	"log"
	"net"

	"github.com/hashicorp/yamux"
)

type Server struct {
	Registry  *TunnelRegistry
	Port      string
	TLSConfig *tls.Config
}

func NewServer(port string, registry *TunnelRegistry, tlsConfig *tls.Config) *Server {
	return &Server{
		Registry:  registry,
		Port:      port,
		TLSConfig: tlsConfig,
	}
}

func (s *Server) Start() error {
	var listener net.Listener
	var err error

	if s.TLSConfig != nil {
		listener, err = tls.Listen("tcp", s.Port, s.TLSConfig)
	} else {
		listener, err = net.Listen("tcp", s.Port)
	}

	if err != nil {
		return err
	}
	log.Printf("Control Plane listening on %s (TLS=%v)", s.Port, s.TLSConfig != nil)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(conn net.Conn) {
	// Wrap connection with Yamux
	session, err := yamux.Server(conn, nil)
	if err != nil {
		log.Printf("Failed to create yamux session: %v", err)
		conn.Close()
		return
	}

	// Accept the first stream for Handshake
	// The client MUST open a stream immediately to authenticate.
	stream, err := session.Accept()
	if err != nil {
		log.Printf("Failed to accept handshake stream: %v", err)
		session.Close()
		return
	}

	// Perform Handshake
	// 1. Auth
	var authReq protocol.AuthRequest
	if err := json.NewDecoder(stream).Decode(&authReq); err != nil {
		log.Printf("Handshake read error: %v", err)
		session.Close()
		return
	}

	user, err := storage.ValidateToken(authReq.Token)
	if err != nil {
		s.sendError(stream, "Invalid Token")
		session.Close()
		return
	}

	// 2. Tunnel Request
	var tunnelReq protocol.TunnelRequest
	if err := json.NewDecoder(stream).Decode(&tunnelReq); err != nil {
		log.Printf("Handshake read error: %v", err)
		session.Close()
		return
	}

	var boundDomains []string
	for _, domain := range tunnelReq.RequestedDomains {
		if storage.ValidateDomainOwnership(domain, user.ID) {
			s.Registry.Register(domain, session)
			boundDomains = append(boundDomains, domain)
			log.Printf("Bound domain %s for user %s", domain, user.Email)
		} else {
			log.Printf("Domain %s check failed for user %s", domain, user.Email)
		}
	}

	if len(boundDomains) == 0 {
		s.sendError(stream, "No valid domains requested or authorized")
		session.Close()
		return
	}

	// 3. Success Response
	resp := protocol.InitResponse{
		Success:      true,
		BoundDomains: boundDomains,
	}
	json.NewEncoder(stream).Encode(resp)

	// Keep session alive. Monitor for close to cleanup.
	// We can block on session.CloseChan or something similar, or just wait.
	// Yamux doesn't have a direct "Wait" on Session, but the session will close if the underlying conn closes.
	// We should monitor the session health to unregister domains.
	go func() {
		<-session.CloseChan()
		log.Printf("Session closed for user %s. Cleaning up domains.", user.Email)
		for _, d := range boundDomains {
			s.Registry.Unregister(d)
		}
	}()
}

func (s *Server) sendError(stream net.Conn, msg string) {
	resp := protocol.InitResponse{
		Success: false,
		Error:   msg,
	}
	json.NewEncoder(stream).Encode(resp)
}
