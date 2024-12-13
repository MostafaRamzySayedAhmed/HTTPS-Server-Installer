package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"crypto/x509"
	"crypto/ecdsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"os"
	"time"
	"crypto/pem"
	"crypto/x509/pkix"
	"math/big"
)

func handler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, you've reached the secure server!")
}

func generateCert() (*tls.Certificate, error) {
	// Generate private key
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Generate self-signed certificate
	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"My Company"},
		},
		NotBefore:   notBefore,
		NotAfter:    notAfter,
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	// Save the certificate and key
	certFile, err := os.Create("cert.pem")
	if err != nil {
		return nil, err
	}
	defer certFile.Close()

	pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes})

	keyFile, err := os.Create("key.pem")
	if err != nil {
		return nil, err
	}
	defer keyFile.Close()

	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pem.Encode(keyFile, &pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return &tls.Certificate{
		Certificate: [][]byte{certBytes},
		PrivateKey:  priv,
	}, nil
}

func main() {
	// Generate the self-signed certificate
	cert, err := generateCert()
	if err != nil {
		log.Fatalf("Failed to generate certificate: %v", err)
	}

	// Set up TLS server
	server := &http.Server{
		Addr: ":443",
		Handler: http.HandlerFunc(handler),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{*cert},
		},
	}

	log.Println("Starting HTTPS server on port 443...")
	log.Fatal(server.ListenAndServeTLS("cert.pem", "key.pem"))
}
