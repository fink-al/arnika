package config

import (
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config contains the configuration values for the arnika service.
type Config struct {
	ListenAddress          string                     // LISTEN_ADDRESS, Address to listen on for incoming connections
	ServerAddress          string                     // SERVER_ADDRESS, Address of the arnika server
	Certificate            string                     // CERTIFICATE, Path to the client certificate file
	PrivateKey             string                     // PRIVATE_KEY, Path to the client key file
	CACertificate          string                     // CA_CERTIFICATE, Path to the CA certificate file
	KMSURL                 string                     // KMS_URL, URL of the KMS server
	KMSHTTPTimeout         time.Duration              // KMS_HTTP_TIMEOUT, HTTP connection timeout
	Interval               time.Duration              // INTERVAL, Interval between key updates
	WireGuardInterface     string                     // WIREGUARD_INTERFACE, Name of the WireGuard interface to configure
	WireguardPeerPublicKey string                     // WIREGUARD_PEER_PUBLIC_KEY, Public key of the WireGuard peer
	PrivateMLKEMKey        *mlkem.DecapsulationKey768 // PRIVATE_MLKEM_KEY, Base64-encoded MLKEM-768 private key (decapsulation key)
	TrustedKeys            []string                   // TRUSTED_KEYS, List of trusted public keys for the WireGuard peers (separated by commas)
}

// Parse parses the configuration values from environment variables and returns a Config pointer.
//
// No parameters.
// Returns a pointer to a Config struct and an error.
func Parse() (*Config, error) {
	config := &Config{}
	var err error
	config.ListenAddress, err = getEnv("LISTEN_ADDRESS")
	if err != nil {
		return nil, err
	}
	config.ServerAddress, err = getEnv("SERVER_ADDRESS")
	if err != nil {
		return nil, err
	}
	config.Certificate = getEnvOrDefault("CERTIFICATE", "")
	config.PrivateKey = getEnvOrDefault("PRIVATE_KEY", "")
	config.CACertificate = getEnvOrDefault("CA_CERTIFICATE", "")
	config.KMSURL, err = getEnv("KMS_URL")
	if err != nil {
		return nil, err
	}
	kmsHTTPTimeout, err := time.ParseDuration(getEnvOrDefault("KMS_HTTP_TIMEOUT", "10s"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse KMS_HTTP_TIMEOUT: %w", err)
	}
	config.KMSHTTPTimeout = kmsHTTPTimeout
	interval, err := time.ParseDuration(getEnvOrDefault("INTERVAL", "10s"))
	if err != nil {
		return nil, fmt.Errorf("failed to parse INTERVAL: %w", err)
	}
	config.Interval = interval
	config.WireGuardInterface, err = getEnv("WIREGUARD_INTERFACE")
	if err != nil {
		return nil, err
	}
	config.WireguardPeerPublicKey, err = getEnv("WIREGUARD_PEER_PUBLIC_KEY")
	if err != nil {
		return nil, err
	}
	mk, err := getEnv("PRIVATE_MLKEM_KEY")
	if err != nil {
		return nil, err
	}
	decodedKey, err := base64.StdEncoding.DecodeString(mk)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PRIVATE_MLKEM_KEY from base64: %w", err)
	}
	decKey, err := mlkem.NewDecapsulationKey768(decodedKey)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PRIVATE_MLKEM_KEY: %w", err)
	}
	config.PrivateMLKEMKey = decKey
	trustedKeys := getEnvOrDefault("TRUSTED_KEYS", "")
	if trustedKeys != "" {
		config.TrustedKeys = strings.Split(trustedKeys, ",")
	}
	return config, nil
}

// GetEnvOrDefault returns the value of the environment variable named by the key.
// If the variable is not present, returns defaultValue without checking
// the rest of the environment
//
// Parameters:
// - key: the name of the environment variable to retrieve the value from.
// - defaultValue: the default value to return if the environment variable is not present.
//
// Return type:
// - string: the value of the environment variable, or the default value if the
// environment variable is not present.
func getEnvOrDefault(key, defaultValue string) string {
	v := os.Getenv(key)
	if v == "" {
		return defaultValue
	}
	return v
}

// getEnv retrieves the value of the environment variable named by the key
//
// Parameters:
// - key: the name of the environment variable to retrieve the value from.
//
// Return type:
// - string: the value of the environment variable.
// - error: an error if the environment variable is not present.
func getEnv(key string) (string, error) {
	v := os.Getenv(key)
	if v == "" {
		return "", fmt.Errorf("Failed to get environment variable: %s", key)
	}
	return v, nil
}
