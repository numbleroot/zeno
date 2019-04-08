package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"
)

// GenTLSCertAndConf takes care of generating an
// ephemeral TLS certificate based on Elliptic Curve
// Cryptography for supplied FQDN and IP address to
// listen on. A properly configured TLS configuration
// and the PEM-encoded certificate are returned.
// This function takes heavy inspiration from:
// https://golang.org/src/crypto/tls/generate_cert.go
func GenTLSCertAndConf(listenFQDN string, listenIP string) (*tls.Config, []byte, error) {

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
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{listenFQDN},
		IPAddresses:           []net.IP{net.ParseIP(listenIP)},
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
