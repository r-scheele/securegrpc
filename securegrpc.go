package securegrpc

import (
	"log"
	"net"

	"google.golang.org/grpc"
)

func main() {
	cfg := &Config{
		TLSCertPath: "path/to/server.crt",
		TLSKeyPath:  "path/to/server.key",
		CACertPath:  "path/to/ca.crt",
		ACLRules:    "path/to/acl.json",
	}

	creds, err := NewSecureGRPCCredentials(cfg)
	if err != nil {
		log.Fatalf("Failed to create credentials: %v", err)
	}

	server := grpc.NewServer(
		grpc.Creds(creds.ServerCreds),
		grpc.UnaryInterceptor(creds.UnaryInterceptor),
		grpc.StreamInterceptor(creds.StreamInterceptor),
	)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Println("Server starting on :50051...")
	if err := server.Serve(lis); err != nil {
		log.Fatalf("Failed to serve: %v", err)
	}
}
