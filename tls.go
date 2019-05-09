package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"math/big"
	"net"
	"time"
)

// GenPKITLSConf puts together a strong TLS
// configuration to be used when contacting the
// PKI server. It expects the certificate path
// of the PKI server.
func GenPKITLSConf(certPath string) (*tls.Config, error) {

	// Read PKI server TLS certificate from
	// specified file system location.
	pkiCert, err := ioutil.ReadFile(certPath)
	if err != nil {
		return nil, err
	}

	// Create new empty cert pool.
	pkiCertRoot := x509.NewCertPool()

	// Attempt to add the loaded PKI server certificate.
	ok := pkiCertRoot.AppendCertsFromPEM(pkiCert)
	if !ok {
		return nil, fmt.Errorf("failed appending loaded PKI server TLS certificate to pool")
	}

	return &tls.Config{
		RootCAs:            pkiCertRoot,
		InsecureSkipVerify: false,
		MinVersion:         tls.VersionTLS13,
		CurvePreferences:   []tls.CurveID{tls.X25519},
	}, nil
}

// GenPubTLSCertAndConf takes care of generating an
// ephemeral TLS certificate based on Elliptic Curve
// Cryptography for supplied FQDN and IP address to
// listen on. A properly configured TLS configuration
// and the PEM-encoded certificate are returned.
// This function takes heavy inspiration from:
// https://golang.org/src/crypto/tls/generate_cert.go
func GenPubTLSCertAndConf(listenFQDN string, listenIPs []string) (*tls.Config, []byte, error) {

	now := time.Now()

	// Generate new ephemeral P384 EC secret and public key.
	secKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	pubKey := &secKey.PublicKey

	// Obtain marshaled representation of secret key.
	secKeyMarsh, err := x509.MarshalECPrivateKey(secKey)
	if err != nil {
		return nil, nil, err
	}

	// Generate a random serial number.
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}

	// Prepare certificate template.
	certTempl := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Zeno mix-net"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(10 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	// Ensure IPs are only added once.
	listenIPsMap := make(map[string]bool)
	for i := range listenIPs {
		listenIPsMap[listenIPs[i]] = true
	}

	// Parse and add all supplied IP addresses.
	for ip := range listenIPsMap {
		certTempl.IPAddresses = append(certTempl.IPAddresses, net.ParseIP(ip))
	}

	// Only specify an FQDN if supplied argument is not empty.
	if listenFQDN != "" {
		certTempl.DNSNames = []string{listenFQDN}
	}

	// Generate DER representation of certificate.
	certDER, err := x509.CreateCertificate(rand.Reader, certTempl, certTempl, pubKey, secKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode certificate to PEM format in memory.
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Encode secret key to PEM format in memory.
	secKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: secKeyMarsh,
	})

	// Load prepared certificate and secret key into
	// TLS certificate representation.
	tlsCert, err := tls.X509KeyPair(certPEM, secKeyPEM)
	if err != nil {
		return nil, nil, err
	}

	return &tls.Config{
		Certificates:           []tls.Certificate{tlsCert},
		InsecureSkipVerify:     false,
		MinVersion:             tls.VersionTLS13,
		CurvePreferences:       []tls.CurveID{tls.X25519},
		SessionTicketsDisabled: true,
	}, certPEM, nil
}
