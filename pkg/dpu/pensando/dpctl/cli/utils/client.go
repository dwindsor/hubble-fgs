//-----------------------------------------------------------------------------
// {C} Copyright 2023 AMD Inc. All rights reserved
//-----------------------------------------------------------------------------

package utils

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"strconv"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

var (
	GRPCDefaultBaseURL = "127.0.0.1"
	PDSGRPCDefaultPort = "11357"
)

const (
	UpgGRPCDefaultPort            = "11358" // PDS_GRPC_PORT_UPGMGR
	HAGRPCDefaultPort             = "11365" // PDS_FSMMGR_HA_GRPC_PORT
	pdsSecureGRPCDefaultPath      = "/data/pensando/secure_grpc/"
	pdsSecureGRPCCACert           = "root/ca.crt"
	pdsSecureGRPCClientKey        = "client/client.key"
	pdsSecureGRPCClientCert       = "client/client.crt"
	pdsGRPCDefaultPortConnTimeout = 30 // timeout in seconds
	operdGRPCDefaultPort          = "11359"
	operdCorePluginGRPCPort       = "11360"
	SsdkAppGRPCDefaultPort        = "11364"
)

// timeout for grpc port conn
func getClientPortConnTimeout() (uint, error) {
	timeoutStr, present := os.LookupEnv("GRPC_CONN_TIMEOUT")
	if !present {
		return pdsGRPCDefaultPortConnTimeout, nil
	}
	timeout, err := strconv.Atoi(timeoutStr)
	if err != nil || timeout < 0 {
		return 0, fmt.Errorf("Failed to parse GRPC_CONN_TIMEOUT(%s), err | %+v",
			timeoutStr, err)
	}
	return uint(timeout), nil
}

// timeout for rpc calls
func getClientReqTimeout() (uint, error) {
	timeoutStr, present := os.LookupEnv("GRPC_TIMEOUT")
	if !present {
		return 0, nil
	}
	timeout, err := strconv.Atoi(timeoutStr)
	if err != nil || timeout < 0 {
		return 0, fmt.Errorf("Failed to parse GRPC_TIMEOUT(%s), err | %+v",
			timeoutStr, err)
	}
	return uint(timeout), nil
}

// function to load tls credentials
func loadTLSCredentials() (credentials.TransportCredentials, error) {
	// create a certificate pool from the certificate authority
	certPool := x509.NewCertPool()
	grpcPath, present := os.LookupEnv("SECURE_GRPC_PATH")
	if present == false {
		grpcPath = pdsSecureGRPCDefaultPath
	}
	rootCA := grpcPath + pdsSecureGRPCCACert
	ca, err := ioutil.ReadFile(rootCA)
	if err != nil {
		return nil, fmt.Errorf("could not read ca certificate: %s", err)
	}

	// append the certificates from the CA
	if ok := certPool.AppendCertsFromPEM(ca); !ok {
		return nil, fmt.Errorf("failed to append ca certs")
	}

	config := &tls.Config{
		RootCAs:            certPool,
		InsecureSkipVerify: true,
	}

	// check for presence of client certificate and key,
	// if present attempt mutual TLS
	clientKey := grpcPath + pdsSecureGRPCClientKey
	_, err = os.Stat(clientKey)
	if err != nil {
		return credentials.NewTLS(config), nil
	}
	clientCert := grpcPath + pdsSecureGRPCClientCert
	_, err = os.Stat(clientCert)
	if err != nil {
		return credentials.NewTLS(config), nil
	}

	// load the client certificates for mutual TLS
	certificate, err := tls.LoadX509KeyPair(clientCert, clientKey)
	if err != nil {
		return nil, fmt.Errorf("could not load client key pair: %s", err)
	}
	config.Certificates = []tls.Certificate{certificate}

	return credentials.NewTLS(config), nil
}

// createNewGRPCClient creates a grpc connection to HAL
func createNewSecureGRPCClient() (*grpc.ClientConn, error) {
	pdsPort := os.Getenv("HAL_GRPC_PORT")
	if pdsPort == "" {
		pdsPort = PDSGRPCDefaultPort
	}
	srvURL := GRPCDefaultBaseURL + ":" + pdsPort

	// create the client TLS credentials
	creds, err := loadTLSCredentials()
	if err != nil {
		return nil, err
	}
	timeout, err := getClientPortConnTimeout()
	if err != nil {
		return nil, err
	}
	ctxt, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeout)*time.Second)
	defer cancel()

	var grpcOpts []grpc.DialOption
	grpcOpts = append(grpcOpts, grpc.WithMaxMsgSize(math.MaxInt32-1))
	grpcOpts = append(grpcOpts, grpc.WithBlock())
	grpcOpts = append(grpcOpts, grpc.WithTransportCredentials(creds))
	rpcClient, err := grpc.DialContext(ctxt, srvURL, grpcOpts...)
	if err != nil {
		return nil, err
	}
	return rpcClient, err
}

func tlsKeyCertExists() bool {
	grpcPath, present := os.LookupEnv("SECURE_GRPC_PATH")
	if present == false {
		grpcPath = pdsSecureGRPCDefaultPath
	}
	rootCA := grpcPath + pdsSecureGRPCCACert
	_, err := os.Stat(rootCA)
	if err == nil {
		return true
	}
	return false
}

// createNewGRPCClient creates a grpc connection to HAL
// we first check if secure grpc exists and if not fallback
// to regular grpc
func createNewGRPCClient() (*grpc.ClientConn, error) {
	if tlsKeyCertExists() == true {
		// first try secure grpc
		rpcClient, err := createNewSecureGRPCClient()
		if err == nil {
			return rpcClient, err
		}
	}
	// try unsecure grpc
	pdsPort := os.Getenv("HAL_GRPC_PORT")
	if pdsPort == "" {
		pdsPort = PDSGRPCDefaultPort
	}
	srvURL := GRPCDefaultBaseURL + ":" + pdsPort
	timeout, err := getClientPortConnTimeout()
	if err != nil {
		return nil, err
	}

	ctxt, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeout)*time.Second)
	defer cancel()

	var grpcOpts []grpc.DialOption
	grpcOpts = append(grpcOpts, grpc.WithMaxMsgSize(math.MaxInt32-1))
	grpcOpts = append(grpcOpts, grpc.WithInsecure())
	grpcOpts = append(grpcOpts, grpc.WithBlock())
	rpcClient, err := grpc.DialContext(ctxt, srvURL, grpcOpts...)
	if err != nil {
		log.Fatalf("Creating gRPC Client failed, server URL: %s, err %v",
			srvURL, err)
		return nil, err
	}
	return rpcClient, err
}

func CreateNewPdsGRPClient() (*grpc.ClientConn, context.Context,
	context.CancelFunc, error) {
	var ctxt context.Context
	var cancel context.CancelFunc

	client, err := createNewGRPCClient()
	if err != nil {
		return nil, nil, nil, err
	}
	timeout, err := getClientReqTimeout()
	if err != nil {
		return nil, nil, nil, err
	}
	if timeout != 0 {
		ctxt, cancel = context.WithTimeout(context.Background(),
			time.Duration(timeout)*time.Second)
	} else {
		ctxt, cancel = context.WithCancel(context.Background())
	}
	return client, ctxt, cancel, nil
}

func CreateNewSsdkAppGRPCClient() (*grpc.ClientConn, context.Context,
	context.CancelFunc, error) {
	var ctxt context.Context
	var cancel context.CancelFunc

	ssdkPort := os.Getenv("SSDK_DP_APP_GRPC_PORT")
	if ssdkPort == "" {
		ssdkPort = SsdkAppGRPCDefaultPort
	}
	srvURL := GRPCDefaultBaseURL + ":" + ssdkPort
	var grpcOpts []grpc.DialOption
	grpcOpts = append(grpcOpts, grpc.WithMaxMsgSize(math.MaxInt32-1))
	grpcOpts = append(grpcOpts, grpc.WithInsecure())
	rpcClient, err := grpc.Dial(srvURL, grpcOpts...)

	if err != nil {
		log.Fatalf("Creating ssdk app gRPC Client failed. Server URL: %s", srvURL)
		return nil, nil, nil, err
	}
	timeout, ret := getClientReqTimeout()
	if ret != nil {
		return nil, nil, nil, ret
	}
	if timeout != 0 {
		ctxt, cancel = context.WithTimeout(context.Background(),
			time.Duration(timeout)*time.Second)
	} else {
		ctxt, cancel = context.WithCancel(context.Background())
	}
	return rpcClient, ctxt, cancel, nil
}

// CreateNewOperdGRPCClient creates a grpc connection to operd
func CreateNewOperdGRPCClient() (*grpc.ClientConn, error) {
	operdPort := operdGRPCDefaultPort
	srvURL := GRPCDefaultBaseURL + ":" + operdPort
	var grpcOpts []grpc.DialOption
	grpcOpts = append(grpcOpts, grpc.WithMaxMsgSize(math.MaxInt32-1))
	grpcOpts = append(grpcOpts, grpc.WithInsecure())
	rpcClient, err := grpc.Dial(srvURL, grpcOpts...)

	if err != nil {
		log.Fatalf("Creating operd gRPC Client failed. Server URL: %s", srvURL)
		return nil, err
	}
	return rpcClient, err
}

// CreateNewOperdCorePluginGRPCClient creates a grpc connection
// to operd core plugin
func CreateNewOperdCorePluginGRPCClient() (*grpc.ClientConn, error) {
	operdPort := operdCorePluginGRPCPort
	srvURL := GRPCDefaultBaseURL + ":" + operdPort
	var grpcOpts []grpc.DialOption
	grpcOpts = append(grpcOpts, grpc.WithMaxMsgSize(math.MaxInt32-1))
	grpcOpts = append(grpcOpts, grpc.WithInsecure())
	rpcClient, err := grpc.Dial(srvURL, grpcOpts...)

	if err != nil {
		log.Fatalf("Creating operd core plugin gRPC Client failed. Server URL: %s", srvURL)
		return nil, err
	}
	return rpcClient, err
}

// CreateNewUpgGRPCClient creates a grpc connection to Upg
func CreateNewUpgGRPCClient() (*grpc.ClientConn, error) {
	pdsPort := os.Getenv("PDS_GRPC_PORT_UPGMGR")
	if pdsPort == "" {
		pdsPort = UpgGRPCDefaultPort
	}
	srvURL := GRPCDefaultBaseURL + ":" + pdsPort
	var grpcOpts []grpc.DialOption
	grpcOpts = append(grpcOpts, grpc.WithMaxMsgSize(math.MaxInt32-1))
	grpcOpts = append(grpcOpts, grpc.WithInsecure())
	rpcClient, err := grpc.Dial(srvURL, grpcOpts...)

	if err != nil {
		log.Fatalf("Creating UPG gRPC Client failed. Server URL: %s", srvURL)
		return nil, err
	}

	return rpcClient, err
}

// CreateNewHAGRPCClient creates a grpc connection to Upg
func CreateNewHAGRPCClient() (*grpc.ClientConn, error) {
	pdsPort := os.Getenv("PDS_FSMMGR_HA_GRPC_PORT")
	if pdsPort == "" {
		pdsPort = HAGRPCDefaultPort
	}
	srvURL := GRPCDefaultBaseURL + ":" + pdsPort
	var grpcOpts []grpc.DialOption
	grpcOpts = append(grpcOpts, grpc.WithMaxMsgSize(math.MaxInt32-1))
	grpcOpts = append(grpcOpts, grpc.WithInsecure())
	rpcClient, err := grpc.Dial(srvURL, grpcOpts...)

	if err != nil {
		log.Fatalf("Creating flow sync gRPC Client failed. Server URL: %s", srvURL)
		return nil, err
	}

	return rpcClient, err
}
