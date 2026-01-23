// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchpolicy

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestValidateCEL(t *testing.T) {
	tests := []struct {
		name    string
		obj     map[string]interface{}
		wantErr bool
	}{
		{
			name: "Valid policy with VRF only on source",
			obj: map[string]interface{}{
				"apiVersion": "isovalent.com/v1alpha1",
				"kind":       "SmartSwitchNetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "test-policy",
					"namespace": "default",
				},
				"spec": map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"action": "allow",
							"source": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "10.0.0.0/8",
										"vrf":  "internal",
									},
								},
							},
							"destination": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "192.168.1.0/24",
									},
								},
								"protoPorts": []interface{}{
									map[string]interface{}{
										"protocol": "TCP",
										"port":     int64(443),
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Valid policy with VLAN only on source",
			obj: map[string]interface{}{
				"apiVersion": "isovalent.com/v1alpha1",
				"kind":       "SmartSwitchNetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "test-policy",
					"namespace": "default",
				},
				"spec": map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"action": "allow",
							"source": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "10.0.0.0/8",
										"vlan": int64(100),
									},
								},
							},
							"destination": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "192.168.1.0/24",
									},
								},
								"protoPorts": []interface{}{
									map[string]interface{}{
										"protocol": "TCP",
										"port":     int64(443),
									},
								},
							},
						},
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Invalid policy with both VRF and VLAN on source",
			obj: map[string]interface{}{
				"apiVersion": "isovalent.com/v1alpha1",
				"kind":       "SmartSwitchNetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "test-policy",
					"namespace": "default",
				},
				"spec": map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"action": "allow",
							"source": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "10.0.0.0/8",
										"vrf":  "internal",
										"vlan": int64(100),
									},
								},
							},
							"destination": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "192.168.1.0/24",
									},
								},
								"protoPorts": []interface{}{
									map[string]interface{}{
										"protocol": "TCP",
										"port":     int64(443),
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid policy with both VRF and VLAN on destination",
			obj: map[string]interface{}{
				"apiVersion": "isovalent.com/v1alpha1",
				"kind":       "SmartSwitchNetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "test-policy",
					"namespace": "default",
				},
				"spec": map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"action": "allow",
							"source": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "10.0.0.0/8",
									},
								},
							},
							"destination": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "192.168.1.0/24",
										"vrf":  "external",
										"vlan": int64(200),
									},
								},
								"protoPorts": []interface{}{
									map[string]interface{}{
										"protocol": "TCP",
										"port":     int64(443),
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "Invalid policy with ICMP protocol specifying port",
			obj: map[string]interface{}{
				"apiVersion": "isovalent.com/v1alpha1",
				"kind":       "SmartSwitchNetworkPolicy",
				"metadata": map[string]interface{}{
					"name":      "test-policy",
					"namespace": "default",
				},
				"spec": map[string]interface{}{
					"rules": []interface{}{
						map[string]interface{}{
							"action": "allow",
							"source": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "10.0.0.0/8",
									},
								},
							},
							"destination": map[string]interface{}{
								"ipBlock": []interface{}{
									map[string]interface{}{
										"cidr": "192.168.1.0/24",
									},
								},
								"protoPorts": []interface{}{
									map[string]interface{}{
										"protocol": "ICMP",
										"port":     int64(8),
									},
								},
							},
						},
					},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			unstr := &unstructured.Unstructured{Object: tt.obj}
			err := ValidateCEL(context.Background(), unstr)
			if tt.wantErr {
				require.Error(t, err, "expected validation error")
			} else {
				require.NoError(t, err, "expected no validation error")
			}
		})
	}
}
