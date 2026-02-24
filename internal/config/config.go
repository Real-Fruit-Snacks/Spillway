package config

// ListenerConfig holds configuration for a listener instance.
type ListenerConfig struct {
	Mode        string // "reverse" or "bind"
	ListenAddr  string // reverse: listen for agent connections
	ConnectAddr string // bind: connect to agent
	MountPoint  string
	PSK         []byte
	CertPEM     []byte
	KeyPEM      []byte
	ReadOnly    bool
	Quiet       bool // suppress per-connection error logging
	CacheTTL    int  // seconds, default 5
}
