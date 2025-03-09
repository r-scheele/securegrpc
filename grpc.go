package securegrpc

import (
	"encoding/json"
	"fmt"
	"io/ioutil"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// SecureGRPCCredentials bundles all security components
type SecureGRPCCredentials struct {
	ServerCreds       credentials.TransportCredentials
	ClientCreds       credentials.TransportCredentials
	UnaryInterceptor  grpc.UnaryServerInterceptor
	StreamInterceptor grpc.StreamServerInterceptor
}

// NewSecureGRPCCredentials initializes the package
func NewSecureGRPCCredentials(cfg *Config) (*SecureGRPCCredentials, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	// Set up server TLS
	serverCreds, err := NewServerTLSCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create server TLS credentials: %w", err)
	}

	// Set up client TLS
	clientCreds, err := NewClientTLSCredentials(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create client TLS credentials: %w", err)
	}

	// Load ACL rules
	acl, err := loadACL(cfg.ACLRules)
	if err != nil {
		return nil, fmt.Errorf("failed to load ACL rules: %w", err)
	}

	return &SecureGRPCCredentials{
		ServerCreds:       serverCreds,
		ClientCreds:       clientCreds,
		UnaryInterceptor:  UnaryServerInterceptor(acl),
		StreamInterceptor: StreamServerInterceptor(acl),
	}, nil
}

// loadACL loads rules from a JSON file
func loadACL(rulesPath string) (*ACL, error) {
	data, err := ioutil.ReadFile(rulesPath)
	if err != nil {
		return nil, err
	}

	var acl ACL
	if err := json.Unmarshal(data, &acl.Rules); err != nil {
		return nil, err
	}
	return &acl, nil
}
