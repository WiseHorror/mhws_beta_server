package backend

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"mhws_beta_server/config"
	"os"
	"path/filepath"
	"time"
)

// Generate a self-signed root certificate
func generateSelfSignedCert(rootCertFile, rootKeyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	// Setting up a certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"MHWilds Beta Server"},
			Country:      []string{"PT"},
			Locality:     []string{"Lisbon"},
			Province:     []string{"Lisbon"},
			CommonName:   "hjm.rebe.capcom.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // Valid for 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	// Generate a self-signed certificate
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}
	// Encode the certificate into PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	// Encode the private key into PEM format
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	// Save the certificate to a file
	dir := filepath.Dir(rootCertFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(rootCertFile, certPEM, 0644); err != nil {
		return nil, nil, fmt.Errorf("failed to write certificate file: %w", err)
	}
	// Save the private key to a file
	dir = filepath.Dir(rootKeyFile)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
	}
	if err := os.WriteFile(rootKeyFile, privateKeyPEM, 0600); err != nil {
		return nil, nil, fmt.Errorf("failed to write private key file: %w", err)
	}
	return &template, privateKey, nil
}

// Read root certificate and private key
func loadRootCertAndKey(rootCertFile, rootKeyFile string) (*x509.Certificate, *rsa.PrivateKey, error) {
	// Read the certificate file
	certBytes, err := os.ReadFile(rootCertFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read certificate file: %w", err)
	}
	// Read the private key file
	privateKeyBytes, err := os.ReadFile(rootKeyFile)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read private key file: %w", err)
	}
	// Parsing Certificates
	block, _ := pem.Decode(certBytes)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, nil, fmt.Errorf("failed to decode PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}
	// Parsing the private key
	privateKeyBlock, _ := pem.Decode(privateKeyBytes)
	if privateKeyBlock == nil || privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return nil, nil, fmt.Errorf("failed to decode PEM private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}
	return cert, privateKey, nil
}
func GenerateDomainCert(cfg *config.Config) (*tls.Certificate, error) {
	var rootCert *x509.Certificate
	var rootPrivateKey *rsa.PrivateKey
	// Check if the root certificate file exists
	if _, err := os.Stat(cfg.RootCertFile); os.IsNotExist(err) {
		// Generate a self-signed certificate
		rootCert, rootPrivateKey, err = generateSelfSignedCert(cfg.RootCertFile, cfg.RootKeyFile)
		if err != nil {
			return nil, fmt.Errorf("error generating self-signed certificate: %v", err)
		}
	} else {
		// Read root certificate and private key
		rootCert, rootPrivateKey, err = loadRootCertAndKey(cfg.RootCertFile, cfg.RootKeyFile)
		if err != nil {
			return nil, fmt.Errorf("error loading root certificate and key: %v", err)
		}
	}
	// Generate a private key for the sub-certificate
	subjectKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate subject key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Country:            []string{"PT"},
			Organization:       []string{"MHWilds Beta Server"},
			OrganizationalUnit: []string{"IT Department"},
			CommonName:         "hjm.rebe.capcom.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false, // The sub-certificate is not a CA certificate
		DNSNames:              cfg.CertDomain,
	}
	// Use the root certificate and private key to issue a sub-certificate
	certDERBytes, err := x509.CreateCertificate(rand.Reader, &template, rootCert, &subjectKey.PublicKey, rootPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %v", err)
	}
	// Encode the certificate into PEM format
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDERBytes})
	// Encode the private key into PEM format
	subjectKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(subjectKey)})
	// Load the certificate and private key in PEM format into the tls.Certificate structure
	subCert, err := tls.X509KeyPair(certPEM, subjectKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load sub certificate and key: %v", err)
	}
	return &subCert, nil
}
