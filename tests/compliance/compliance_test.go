package compliance_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/cilium/tetragon/pkg/k8s/apis/cilium.io/v1alpha1"
	"github.com/cilium/tetragon/pkg/testutils/sensors"
	"github.com/cilium/tetragon/pkg/tracingpolicy"
	"github.com/isovalent/hubble-fgs/tests/compliance"
	"github.com/isovalent/hubble-fgs/tests/compliance/config"
	"github.com/stretchr/testify/assert"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	_ "github.com/isovalent/hubble-fgs/pkg/sensorinit"
)

func TestMain(m *testing.M) {
	config.Config()
	// TestSensorsRun() will call flag.Parse() for us and set up the config for
	// observer_test_helper.
	res := sensors.TestSensorsRun(m, "compliance")
	os.Exit(res)
}

func testCases() []compliance.Test {
	return []compliance.Test{
		{
			Name: "nginx",
			TracingPolicy: &tracingpolicy.GenericTracingPolicy{
				TypeMeta: v1.TypeMeta{
					Kind:       "TracingPolicy",
					APIVersion: "cilium.io/v1alpha1",
				},
				Metadata: v1.ObjectMeta{
					Name: "http",
				},
				Spec: v1alpha1.TracingPolicySpec{
					Parser: v1alpha1.ParserPolicySpec{
						Http: v1alpha1.HttpSpec{
							Enable: true,
							Selectors: []v1alpha1.HttpSelector{
								{MatchPorts: []uint32{
									8025, 8026, 8027, 8028, 8029,
									8030, 8031, 8032, 8033, 8079,
									8080, 8081, 8082, 8083, 8084,
									8085, 8086, 8087, 8088, 8089,
									8090, 8091, 8092, 8093, 8094,
									8095, 8096, 8097, 8098, 8099,
									8100, 8110, 8111, 8112, 8142,
									8143, 8144, 8145, 8146, 8147,
									8148, 8149, 8150, 8151, 8152,
									8153, 8154, 8181, 8184, 8185,
									8188, 8443, 8444, 8445, 8446,
									8447, 8448, 8449, 80800,
								}},
							},
						},
						Tcp: v1alpha1.TcpPolicySpec{
							Enable: true,
						},
					},
				},
			},
			Steps: []compliance.Stepper{
				&compliance.ProveStep{
					TestDir: ".",
					Checker: nil,
				},
			},
		},
	}
}

func TestCompliance(t *testing.T) {
	for _, ct := range testCases() {
		t.Run(fmt.Sprintf("compliance-%s", ct.Name), func(t *testing.T) {
			assert.NoError(t, ct.BuildAndRun(t))
		})
	}
}
