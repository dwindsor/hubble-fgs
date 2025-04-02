//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package stresstests

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"text/template"
	"time"

	// embed certificate and key files
	_ "embed"

	"github.com/cilium/tetragon/pkg/bpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/observer/observertesthelper"
	"github.com/cilium/tetragon/pkg/testutils"
	enterpriseoth "github.com/isovalent/hubble-fgs/pkg/observer/observertesthelper"
	"github.com/isovalent/hubble-fgs/pkg/sensors/base"
	"github.com/isovalent/hubble-fgs/pkg/testutils/runner"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	//go:embed cert.pem
	certPem []byte

	//go:embed key.pem
	keyPem []byte
)

// Start a TCP listener on a port assigned from the host OS and return the listener and
// the port number tht was assigned.
func tcpListen(ctx context.Context) (net.Listener, int, error) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, -1, err
	}

	go func() {
		<-ctx.Done()
		listener.Close()
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	return listener, port, nil
}

// Start a TLS webserver that accepts connections and sends back any received data.
func startTlsWebServer(ctx context.Context) (int, chan error, error) {
	listener, port, err := tcpListen(ctx)
	if err != nil {
		return port, nil, err
	}

	cert, err := tls.X509KeyPair(certPem, keyPem)
	if err != nil {
		listener.Close()
		return port, nil, err
	}
	listener = tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{cert},
	})

	errChan := make(chan error, 1)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				c, err := listener.Accept()
				if err != nil {
					errChan <- fmt.Errorf("failed to accept incoming connection: %w", err)
					continue
				}
				nCopied, err := io.Copy(c, c)
				logger.GetLogger().Debugf("sent back %d bytes", nCopied)
				if err != nil {
					errChan <- fmt.Errorf("failed to send back bytes: %w", err)
				}
				c.Close()
			}
		}
	}()

	return port, errChan, nil
}

// Wraps a YAML tracing policy so we can essentially accept a *string in testCase without
// being annoying by not being able to take the address in-line of a go string literal.
type tracingPolicy struct {
	string
}

// Describes a TLS stress test case.
type testCase struct {
	// Name of the test case
	name string
	// Tetragon Enterprise tracing policy to load prior to tests.
	// Nil implies that we should not load any BPF programs for this test.
	tracingPolicy *tracingPolicy
	// Number of connections to make in a row.
	numConnections int
}

// Run a test case using t.Run().
func (tc *testCase) run(t *testing.T) {
	t.Run(tc.name, func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()

		port, errChan, err := startTlsWebServer(ctx)
		require.NoError(t, err, "web server should start")
		dialer := &tls.Dialer{
			NetDialer: &net.Dialer{Timeout: 5 * time.Second},
			Config:    &tls.Config{InsecureSkipVerify: true},
		}

		if tc.tracingPolicy != nil {
			var builder strings.Builder
			temp, err := template.New("").Parse(tc.tracingPolicy.string)
			require.NoError(t, err, "template should parse")
			temp.Execute(&builder, map[string]interface{}{
				"port": port,
			})

			err = observertesthelper.WriteConfigFile(testConfigFile, builder.String())
			require.NoError(t, err, "config file should write")

			bpf.CheckOrMountCgroup2()

			base := base.GetInitialSensor()
			_, err = enterpriseoth.GetDefaultObserverWithBase(t, ctx, base, testConfigFile, runner.Conf().TetragonLib)
			require.NoError(t, err, "observer should start")
		}

		for i := 0; i < tc.numConnections; i++ {
			func() {
				logger.GetLogger().WithField("i", i).Info("starting Connect-Request-Response round...")

				// Call this first to ensure error queue is empty before attempting
				// a connection, preventing deadlock.
				select {
				case err := <-errChan:
					require.NoError(t, err, "server should accept connection and send back bytes")
				default:
				}

				conn, err := dialer.DialContext(ctx, "tcp4", fmt.Sprintf("127.0.0.1:%d", port))
				require.NoError(t, err, "dial should succeed")
				defer conn.Close()

				payload := []byte("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
				nWrote, err := conn.Write(payload)
				logger.GetLogger().Debugf("wrote %d bytes", nWrote)
				require.NoError(t, err, "payload should send")

				response := make([]byte, len(payload))
				nRead, err := conn.Read(response)
				logger.GetLogger().Debugf("read %d bytes", nRead)
				require.NoError(t, err, "response should be received")

				assert.Equal(t, response, payload, "server should reply with exact payload")
			}()
		}
	})
}

func TestTlsConnectionsSucceed(t *testing.T) {
	testutils.CaptureLog(t, logger.DefaultLogger)

	testCases := []testCase{
		{
			name:           "tls no tetragon",
			tracingPolicy:  nil,
			numConnections: 10_000,
		},
		{
			name: "tls with tetragon base sensor",
			tracingPolicy: &tracingPolicy{`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "base"`,
			},
			numConnections: 10_000,
		},
		{
			name: "tls with tetragon tls sensor parser not running",
			tracingPolicy: &tracingPolicy{
				`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "tls"
spec:
  parser:
    tls:
      enable: true
      mode: "socket"
    tcp:
      enable: true
                `,
			},
			numConnections: 10_000,
		},
		{
			name: "tls with tetragon tls sensor parser running",
			tracingPolicy: &tracingPolicy{
				`
            apiVersion: cilium.io/v1alpha1
            kind: TracingPolicy
            metadata:
              name: "tls"
            spec:
              parser:
                tls:
                  enable: true
                  mode: "socket"
                  selectors:
                  - matchPorts:
                    - {{ .port }}
                tcp:
                  enable: true
                            `,
			},
			numConnections: 10_000,
		},
		{
			name: "tls with tetragon nop sensor parser running",
			tracingPolicy: &tracingPolicy{
				`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "nop"
spec:
  parser:
    nop:
      enable: true
      selectors:
      - matchPorts:
        - {{ .port }}
    tcp:
      enable: true
                `,
			},
			numConnections: 10_000,
		},
		{
			name: "tls with tetragon http sensor parser running",
			tracingPolicy: &tracingPolicy{
				`
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: "http"
spec:
  parser:
    http:
      enable: true
      selectors:
      - matchPorts:
        - {{ .port }}
    tcp:
      enable: true
                `,
			},
			numConnections: 10_000,
		},
	}

	for _, testCase := range testCases {
		testCase.run(t)
	}
}
