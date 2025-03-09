package securegrpc

import (
	"context"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ACLRule defines a rule for a client
type ACLRule struct {
	ClientCN string   // Client certificate Common Name
	Methods  []string // Allowed gRPC methods (e.g., "/service.Method")
}

// ACL holds all rules
type ACL struct {
	Rules []ACLRule
}

// Authorize checks if a client can call a method
func (a *ACL) Authorize(ctx context.Context, fullMethod string) error {
	// Get peer info from context
	p, ok := peer.FromContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "no peer found")
	}

	// Extract TLS info
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return status.Error(codes.Unauthenticated, "unexpected peer transport credentials")
	}

	// Verify client certificate
	if len(tlsInfo.State.VerifiedChains) == 0 || len(tlsInfo.State.VerifiedChains[0]) == 0 {
		return status.Error(codes.Unauthenticated, "could not verify peer certificate")
	}

	clientCN := tlsInfo.State.VerifiedChains[0][0].Subject.CommonName

	// Check ACL rules
	for _, rule := range a.Rules {
		if rule.ClientCN == clientCN {
			for _, method := range rule.Methods {
				if method == fullMethod {
					return nil // Allowed
				}
			}
		}
	}

	return status.Error(codes.PermissionDenied, "client not authorized for this method")
}
