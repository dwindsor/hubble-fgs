package cert

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"

	"google.golang.org/grpc/credentials"
)

var insecureTLS bool

func SetInsecureTLS(b bool) { insecureTLS = b }
func isInsecureTLS() bool   { return insecureTLS }

func GenServerCred(isMutual bool, cltCaCert string) (credentials.TransportCredentials, error) {
	// Create the tls config
	config := &tls.Config{
		NextProtos: []string{"h2"},
	}
	if isInsecureTLS() {
		config.InsecureSkipVerify = true
	}

	if isMutual {
		pem, err := os.ReadFile(cltCaCert)
		if err != nil {
			return nil, err
		}

		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("failed to add CA's certificate")
		}
		config.ClientAuth = tls.RequireAndVerifyClientCert
		config.ClientCAs = pool
	} else {
		config.ClientAuth = tls.NoClientCert
	}
	return credentials.NewTLS(config), nil
}

func GenClientCred(isMutual bool, cltCert, cltKey string) (credentials.TransportCredentials, error) {
	var cred credentials.TransportCredentials

	config := &tls.Config{
		NextProtos: []string{"h2"},
	}
	if isInsecureTLS() {
		config.InsecureSkipVerify = true
	}
	if isMutual {
		cert, err := tls.LoadX509KeyPair(cltCert, cltKey)
		if err != nil {
			return cred, err
		}

		// Create the tls config
		config.Certificates = []tls.Certificate{cert}
	}
	cred = credentials.NewTLS(config)
	return cred, nil
}
