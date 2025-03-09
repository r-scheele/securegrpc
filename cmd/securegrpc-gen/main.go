package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"

	"github.com/r-scheele/securegrpc/internal/gen" // Replace with your actual module path
	"gopkg.in/yaml.v3"
)

// Config defines the structure of the YAML configuration file.
type Config struct {
	GenerateCA     bool             `yaml:"generate_ca"`     // Whether to generate the CA
	GenerateServer bool             `yaml:"generate_server"` // Whether to generate the server certificate
	GenerateClient bool             `yaml:"generate_client"` // Whether to generate the client certificate
	CA             gen.CAConfig     `yaml:"ca"`
	Server         gen.ServerConfig `yaml:"server"`
	Client         gen.ClientConfig `yaml:"client"`
	ACL            struct {
		Generate bool   `yaml:"generate"`
		Output   string `yaml:"output"`
	} `yaml:"acl"`
}

func main() {
	// Define command-line flags
	configPath := flag.String("config", "", "Path to the configuration file")
	outDir := flag.String("out-dir", ".", "Directory to save generated files")
	flag.Parse()

	// Validate that a config file path is provided
	if *configPath == "" {
		log.Fatal("Please provide a configuration file with --config")
	}

	// Read the configuration file
	data, err := os.ReadFile(*configPath)
	if err != nil {
		log.Fatalf("Error reading config file: %v", err)
	}

	// Parse the YAML configuration into the Config struct
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Fatalf("Error parsing config file: %v", err)
	}

	// Ensure the output directory exists
	if err := os.MkdirAll(*outDir, 0755); err != nil {
		log.Fatalf("Error creating output directory: %v", err)
	}

	// Generate CA certificate and key if requested
	if cfg.GenerateCA {
		if err := gen.GenerateCA(&cfg.CA, *outDir); err != nil {
			log.Fatalf("Error generating CA: %v", err)
		}
	}

	// Generate server certificate and key if requested
	if cfg.GenerateServer {
		if err := gen.GenerateServerCert(&cfg.Server, *outDir); err != nil {
			log.Fatalf("Error generating server certificate: %v", err)
		}
	}

	// Generate client certificate and key if requested
	if cfg.GenerateClient {
		if err := gen.GenerateClientCert(&cfg.Client, *outDir); err != nil {
			log.Fatalf("Error generating client certificate: %v", err)
		}
	}

	// Generate ACL rules file if specified in the config
	if cfg.ACL.Generate {
		aclPath := filepath.Join(*outDir, cfg.ACL.Output)
		if err := gen.GenerateACL(cfg.Client.ServiceName, aclPath); err != nil {
			log.Fatalf("Error generating ACL rules: %v", err)
		}
	}

	// Success message
	log.Println("Successfully generated requested files in", *outDir)
}
