package server

import (
	"sync"

	"github.com/hashicorp/yamux"
)

// TunnelRegistry manages the mapping between hostnames and active Yamux sessions.
type TunnelRegistry struct {
	mu       sync.RWMutex
	sessions map[string]*yamux.Session
}

func NewTunnelRegistry() *TunnelRegistry {
	return &TunnelRegistry{
		sessions: make(map[string]*yamux.Session),
	}
}

// Register maps a hostname to a session.
func (r *TunnelRegistry) Register(hostname string, session *yamux.Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[hostname] = session
}

// Unregister removes a mapping.
func (r *TunnelRegistry) Unregister(hostname string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, hostname)
}

// GetSession returns the session for a given hostname.
func (r *TunnelRegistry) GetSession(hostname string) (*yamux.Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sess, ok := r.sessions[hostname]
	return sess, ok
}
