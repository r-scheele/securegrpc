package securegrpc

import "errors"

// Config holds settings for secure gRPC services
type Config struct {
	TLSCertPath string // Path to TLS certificate
	TLSKeyPath  string // Path to TLS private key
	CACertPath  string // Path to CA certificate for mTLS
	ACLRules    string // Path to ACL rules file
}

// Validate ensures the config is complete
func (c *Config) Validate() error {
	if c.TLSCertPath == "" || c.TLSKeyPath == "" || c.CACertPath == "" {
		return errors.New("TLS certificate, key, and CA certificate paths are required")
	}
	return nil
}
