package gen

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// CAConfig holds the configuration for the CA certificate.
type CAConfig struct {
	Country      string `yaml:"country"`
	State        string `yaml:"state"`
	Locality     string `yaml:"locality"`
	Organization string `yaml:"organization"`
	CommonName   string `yaml:"common_name"`
	KeySize      int    `yaml:"key_size,omitempty"`      // Optional, defaults to 4096
	ValidityDays int    `yaml:"validity_days,omitempty"` // Optional, defaults to 365
}

// ServerConfig holds the configuration for the server certificate.
type ServerConfig struct {
	ServiceName  string   `yaml:"service_name"`
	IPs          []string `yaml:"ips,omitempty"`           // Multiple IPs for SANs
	Domains      []string `yaml:"domains,omitempty"`       // Multiple domains for SANs
	IP           string   `yaml:"ip,omitempty"`            // Single IP (backward compatibility)
	Domain       string   `yaml:"domain,omitempty"`        // Single domain (backward compatibility)
	KeySize      int      `yaml:"key_size,omitempty"`      // Optional, defaults to 4096
	ValidityDays int      `yaml:"validity_days,omitempty"` // Optional, defaults to 365
	KeyUsage     string   `yaml:"key_usage,omitempty"`     // Optional, custom KeyUsage
	ExtKeyUsage  string   `yaml:"ext_key_usage,omitempty"` // Optional, custom ExtKeyUsage
}

// ClientConfig holds the configuration for the client certificate.
type ClientConfig struct {
	ServiceName  string `yaml:"service_name"`
	KeySize      int    `yaml:"key_size,omitempty"`      // Optional, defaults to 4096
	ValidityDays int    `yaml:"validity_days,omitempty"` // Optional, defaults to 365
	KeyUsage     string `yaml:"key_usage,omitempty"`     // Optional, custom KeyUsage
	ExtKeyUsage  string `yaml:"ext_key_usage,omitempty"` // Optional, custom ExtKeyUsage
}

// GenerateCA creates a CA key and certificate.
func GenerateCA(cfg *CAConfig, outDir string) error {
	// Set defaults if not provided
	keySize := cfg.KeySize
	if keySize <= 0 {
		keySize = 4096
	}
	validityDays := cfg.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}

	// Validate key size
	if keySize < 2048 {
		return fmt.Errorf("key size must be at least 2048 bits, got %d", keySize)
	}

	// Generate RSA private key
	caKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate CA key with size %d: %w", keySize, err)
	}

	// Create CA certificate template
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:      []string{cfg.Country},
			Province:     []string{cfg.State},
			Locality:     []string{cfg.Locality},
			Organization: []string{cfg.Organization},
			CommonName:   cfg.CommonName,
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, validityDays),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Self-sign the CA certificate
	caCertDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Define file paths
	caKeyPath := filepath.Join(outDir, "ca.key")
	caCertPath := filepath.Join(outDir, "ca.crt")

	// Save CA private key
	caKeyFile, err := os.OpenFile(caKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open CA key file at %s: %w", caKeyPath, err)
	}
	defer caKeyFile.Close()
	if err := pem.Encode(caKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caKey)}); err != nil {
		return fmt.Errorf("failed to write CA key to %s: %w", caKeyPath, err)
	}

	// Save CA certificate
	caCertFile, err := os.OpenFile(caCertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open CA cert file at %s: %w", caCertPath, err)
	}
	defer caCertFile.Close()
	if err := pem.Encode(caCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: caCertDER}); err != nil {
		return fmt.Errorf("failed to write CA certificate to %s: %w", caCertPath, err)
	}

	return nil
}

// GenerateServerCert creates a server key and certificate signed by the CA.
func GenerateServerCert(cfg *ServerConfig, outDir string) error {
	// Set defaults if not provided
	keySize := cfg.KeySize
	if keySize <= 0 {
		keySize = 4096
	}
	validityDays := cfg.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}

	// Validate key size
	if keySize < 2048 {
		return fmt.Errorf("key size must be at least 2048 bits, got %d", keySize)
	}

	// Handle backward compatibility: populate IPs and Domains if IP or Domain is set
	ips := cfg.IPs
	if cfg.IP != "" && len(ips) == 0 {
		ips = []string{cfg.IP}
	}
	domains := cfg.Domains
	if cfg.Domain != "" && len(domains) == 0 {
		domains = []string{cfg.Domain}
	}

	// Validate IPs
	ipAddresses := make([]net.IP, 0, len(ips))
	for _, ipStr := range ips {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			return fmt.Errorf("invalid IP address: %s", ipStr)
		}
		ipAddresses = append(ipAddresses, ip)
	}

	// Validate domains
	dnsRegex := regexp.MustCompile(`^[a-zA-Z0-9-.*]+[a-zA-Z0-9]$`)
	for _, domain := range domains {
		if !dnsRegex.MatchString(domain) {
			return fmt.Errorf("invalid DNS name: %s (must be alphanumeric with optional hyphens or dots)", domain)
		}
	}

	// Generate RSA private key
	serverKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate server key with size %d: %w", keySize, err)
	}

	// Load CA certificate and key (assumes they exist if not generated)
	caCertPath := filepath.Join(outDir, "ca.crt")
	caKeyPath := filepath.Join(outDir, "ca.key")
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate not found at %s; generate CA first or provide an existing one", caCertPath)
	}
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("CA key not found at %s; generate CA first or provide an existing one", caKeyPath)
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM from %s", caCertPath)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA key from %s: %w", caKeyPath, err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM from %s", caKeyPath)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Parse KeyUsage and ExtKeyUsage
	keyUsage, err := parseKeyUsage(cfg.KeyUsage)
	if err != nil {
		return fmt.Errorf("invalid key_usage for server: %w", err)
	}
	if keyUsage == 0 {
		keyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	}
	extKeyUsage, err := parseExtKeyUsage(cfg.ExtKeyUsage)
	if err != nil {
		return fmt.Errorf("invalid ext_key_usage for server: %w", err)
	}
	if len(extKeyUsage) == 0 {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	}

	// Create server certificate template
	serverCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: cfg.ServiceName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, validityDays),
		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,
		DNSNames:    domains,
		IPAddresses: ipAddresses,
	}

	// Sign the server certificate with the CA
	serverCertDER, err := x509.CreateCertificate(rand.Reader, serverCert, caCert, &serverKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create server certificate: %w", err)
	}

	// Define file paths
	serverKeyPath := filepath.Join(outDir, "server.key")
	serverCertPath := filepath.Join(outDir, "server.crt")

	// Save server private key
	serverKeyFile, err := os.OpenFile(serverKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open server key file at %s: %w", serverKeyPath, err)
	}
	defer serverKeyFile.Close()
	if err := pem.Encode(serverKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverKey)}); err != nil {
		return fmt.Errorf("failed to write server key to %s: %w", serverKeyPath, err)
	}

	// Save server certificate
	serverCertFile, err := os.OpenFile(serverCertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open server cert file at %s: %w", serverCertPath, err)
	}
	defer serverCertFile.Close()
	if err := pem.Encode(serverCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: serverCertDER}); err != nil {
		return fmt.Errorf("failed to write server certificate to %s: %w", serverCertPath, err)
	}

	return nil
}

// GenerateClientCert creates a client key and certificate signed by the CA.
func GenerateClientCert(cfg *ClientConfig, outDir string) error {
	// Set defaults if not provided
	keySize := cfg.KeySize
	if keySize <= 0 {
		keySize = 4096
	}
	validityDays := cfg.ValidityDays
	if validityDays <= 0 {
		validityDays = 365
	}

	// Validate key size
	if keySize < 2048 {
		return fmt.Errorf("key size must be at least 2048 bits, got %d", keySize)
	}

	// Generate RSA private key
	clientKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("failed to generate client key with size %d: %w", keySize, err)
	}

	// Load CA certificate and key (assumes they exist if not generated)
	caCertPath := filepath.Join(outDir, "ca.crt")
	caKeyPath := filepath.Join(outDir, "ca.key")
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		return fmt.Errorf("CA certificate not found at %s; generate CA first or provide an existing one", caCertPath)
	}
	if _, err := os.Stat(caKeyPath); os.IsNotExist(err) {
		return fmt.Errorf("CA key not found at %s; generate CA first or provide an existing one", caKeyPath)
	}

	caCertPEM, err := os.ReadFile(caCertPath)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate from %s: %w", caCertPath, err)
	}
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return fmt.Errorf("failed to decode CA certificate PEM from %s", caCertPath)
	}
	caCert, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	caKeyPEM, err := os.ReadFile(caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read CA key from %s: %w", caKeyPath, err)
	}
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return fmt.Errorf("failed to decode CA key PEM from %s", caKeyPath)
	}
	caKey, err := x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse CA key: %w", err)
	}

	// Parse KeyUsage and ExtKeyUsage
	keyUsage, err := parseKeyUsage(cfg.KeyUsage)
	if err != nil {
		return fmt.Errorf("invalid key_usage for client: %w", err)
	}
	if keyUsage == 0 {
		keyUsage = x509.KeyUsageDigitalSignature
	}
	extKeyUsage, err := parseExtKeyUsage(cfg.ExtKeyUsage)
	if err != nil {
		return fmt.Errorf("invalid ext_key_usage for client: %w", err)
	}
	if len(extKeyUsage) == 0 {
		extKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	}

	// Create client certificate template
	clientCert := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName: cfg.ServiceName,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(0, 0, validityDays),
		KeyUsage:    keyUsage,
		ExtKeyUsage: extKeyUsage,
	}

	// Sign the client certificate with the CA
	clientCertDER, err := x509.CreateCertificate(rand.Reader, clientCert, caCert, &clientKey.PublicKey, caKey)
	if err != nil {
		return fmt.Errorf("failed to create client certificate: %w", err)
	}

	// Define file paths
	clientKeyPath := filepath.Join(outDir, "client.key")
	clientCertPath := filepath.Join(outDir, "client.crt")

	// Save client private key
	clientKeyFile, err := os.OpenFile(clientKeyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open client key file at %s: %w", clientKeyPath, err)
	}
	defer clientKeyFile.Close()
	if err := pem.Encode(clientKeyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientKey)}); err != nil {
		return fmt.Errorf("failed to write client key to %s: %w", clientKeyPath, err)
	}

	// Save client certificate
	clientCertFile, err := os.OpenFile(clientCertPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open client cert file at %s: %w", clientCertPath, err)
	}
	defer clientCertFile.Close()
	if err := pem.Encode(clientCertFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCertDER}); err != nil {
		return fmt.Errorf("failed to write client certificate to %s: %w", clientCertPath, err)
	}

	return nil
}

// GenerateACL creates a basic ACL rules file.
func GenerateACL(clientServiceName, outputFile string) error {
	aclContent := fmt.Sprintf(`[
    {
        "ClientCN": "%s",
        "Methods": ["/yourproto.YourService/YourMethod"]
    }
]`, clientServiceName)
	if err := os.WriteFile(outputFile, []byte(aclContent), 0644); err != nil {
		return fmt.Errorf("failed to write ACL file to %s: %w", outputFile, err)
	}
	return nil
}

// parseKeyUsage converts a string of comma-separated key usage values into x509.KeyUsage.
func parseKeyUsage(usageStr string) (x509.KeyUsage, error) {
	if usageStr == "" {
		return 0, nil
	}
	usages := map[string]x509.KeyUsage{
		"digitalSignature":  x509.KeyUsageDigitalSignature,
		"contentCommitment": x509.KeyUsageContentCommitment,
		"keyEncipherment":   x509.KeyUsageKeyEncipherment,
		"dataEncipherment":  x509.KeyUsageDataEncipherment,
		"keyAgreement":      x509.KeyUsageKeyAgreement,
		"certSign":          x509.KeyUsageCertSign,
		"crlSign":           x509.KeyUsageCRLSign,
		"encipherOnly":      x509.KeyUsageEncipherOnly,
		"decipherOnly":      x509.KeyUsageDecipherOnly,
	}

	var result x509.KeyUsage
	for _, part := range strings.Split(usageStr, ",") {
		part = strings.TrimSpace(part)
		if usage, ok := usages[part]; ok {
			result |= usage
		} else {
			return 0, fmt.Errorf("unknown key usage: %s", part)
		}
	}
	return result, nil
}

// parseExtKeyUsage converts a string of comma-separated extended key usage values into []x509.ExtKeyUsage.
func parseExtKeyUsage(usageStr string) ([]x509.ExtKeyUsage, error) {
	if usageStr == "" {
		return nil, nil
	}
	usages := map[string]x509.ExtKeyUsage{
		"serverAuth":      x509.ExtKeyUsageServerAuth,
		"clientAuth":      x509.ExtKeyUsageClientAuth,
		"codeSigning":     x509.ExtKeyUsageCodeSigning,
		"emailProtection": x509.ExtKeyUsageEmailProtection,
		"timeStamping":    x509.ExtKeyUsageTimeStamping,
		"ocspSigning":     x509.ExtKeyUsageOCSPSigning,
	}

	var result []x509.ExtKeyUsage
	for _, part := range strings.Split(usageStr, ",") {
		part = strings.TrimSpace(part)
		if usage, ok := usages[part]; ok {
			result = append(result, usage)
		} else {
			return nil, fmt.Errorf("unknown extended key usage: %s", part)
		}
	}
	return result, nil
}
