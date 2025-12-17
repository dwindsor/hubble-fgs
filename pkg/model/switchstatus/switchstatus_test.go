// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package switchstatus

import (
	"reflect"
	"testing"

	"github.com/isovalent/ipa/k8s/apis/isovalent.com/v1alpha1"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// --- Tests ---

func TestSmartSwitchInventoryName(t *testing.T) {
	sss := &SmartSwitchInventory{
		Metadata: metav1.ObjectMeta{Name: "switch1"},
	}
	if sss.Name() != "switch1" {
		require.Equal(t, "switch1", sss.Name())
	}
}

func TestSmartSwitchInventoryStatusObj(t *testing.T) {
	status := v1alpha1.SmartSwitchInventory{SerialNumber: "sn123"}
	sss := &SmartSwitchInventory{Status: status}
	if sss.StatusObj().SerialNumber != "sn123" {
		require.Equal(t, "sn123", sss.StatusObj().SerialNumber)
	}
}

func TestSmartSwitchInventoryGetObjectMeta(t *testing.T) {
	meta := metav1.ObjectMeta{Name: "switch2"}
	sss := &SmartSwitchInventory{Metadata: meta}
	if sss.GetObjectMeta().Name != "switch2" {
		require.Equal(t, "switch2", sss.GetObjectMeta().Name)
	}
}

func TestSmartSwitchInventoryGetObjectMetaStruct(t *testing.T) {
	meta := metav1.ObjectMeta{Name: "switch3"}
	sss := &SmartSwitchInventory{Metadata: meta}
	obj := sss.GetObjectMetaStruct()
	if reflect.TypeOf(obj).String() != "*v1.ObjectMeta" {
		require.Equal(t, "*v1.ObjectMeta", reflect.TypeOf(obj).String())
	}
}

func TestFromYAMLInvalidYAML(t *testing.T) {
	_, err := FromYAML("invalid: yaml: :")
	if err == nil {
		require.Error(t, err, "expected error for invalid YAML")
	}
}

func TestFromYAMLInvalidKind(t *testing.T) {
	yaml := `
apiVersion: isovalent.com/v1alpha1
kind: NotSmartSwitch
metadata:
  name: test
`
	_, err := FromYAML(yaml)
	if err == nil || err.Error() != "unknown CRD kind: NotSmartSwitch" {
		require.EqualError(t, err, "unknown CRD kind: NotSmartSwitch")
	}
}

func TestFromFileFileNotFound(t *testing.T) {
	_, err := FromFile("nonexistent.yaml")
	if err == nil {
		require.Error(t, err, "expected error for missing file")
	}
}

func TestGetSmartSwitchInventory(t *testing.T) {
	testCases := []struct {
		name       string
		setup      func()
		fields     *SmartSwitchInventoryFields
		wantName   string
		wantSerial string
		wantErr    string
	}{
		{
			name:  "Valid",
			setup: func() {},
			fields: &SmartSwitchInventoryFields{
				BiosVersion:     "1.0.0",
				SerialNumber:    "sn123",
				ServiceIP:       "10.0.0.1",
				ServiceMAC:      "aa:bb:cc:dd:ee:ff",
				SoftwareVersion: "v1.2.3",
				DPUInventories: []DPUInventory{
					{
						HardwareModel:   "modelX",
						ID:              "dpu1",
						ManagementIP:    "192.168.1.1",
						PortHigh:        100,
						PortLow:         50,
						SoftwareVersion: "dpu-v1",
					},
				},
			},
			wantName:   "testswitch",
			wantSerial: "sn123",
			wantErr:    "",
		},
		{
			name:  "Zero DPUStatuses",
			setup: func() {},
			fields: &SmartSwitchInventoryFields{
				BiosVersion:     "2.0.0",
				SerialNumber:    "sn456",
				ServiceIP:       "10.0.0.2",
				ServiceMAC:      "ff:ee:dd:cc:bb:aa",
				SoftwareVersion: "v2.3.4",
				DPUInventories:  []DPUInventory{},
			},
			wantName:   "testswitch",
			wantSerial: "sn456",
			wantErr:    "",
		},
		{
			name:  "Empty SerialNumber Not Allowed",
			setup: func() {},
			fields: &SmartSwitchInventoryFields{
				BiosVersion:     "3.0.0",
				SerialNumber:    "",
				ServiceIP:       "10.0.0.3",
				ServiceMAC:      "11:22:33:44:55:66",
				SoftwareVersion: "v3.4.5",
				DPUInventories:  []DPUInventory{},
			},
			wantName:   "testswitch",
			wantSerial: "",
			wantErr:    "SmartSwitch serial number is empty",
		},
		{
			name:  "Nil Name",
			setup: func() {},
			fields: &SmartSwitchInventoryFields{
				BiosVersion:     "4.0.0",
				SerialNumber:    "sn789",
				ServiceIP:       "10.0.0.4",
				ServiceMAC:      "22:33:44:55:66:77",
				SoftwareVersion: "v4.5.6",
				DPUInventories:  []DPUInventory{},
			},
			wantName:   "",
			wantSerial: "sn789",
			wantErr:    "SmartSwitch name is empty",
		},
		{
			name:  "Nil Namespace",
			setup: func() {},
			fields: &SmartSwitchInventoryFields{
				BiosVersion:     "5.0.0",
				SerialNumber:    "sn101",
				ServiceIP:       "10.0.0.5",
				ServiceMAC:      "33:44:55:66:77:88",
				SoftwareVersion: "v5.6.7",
				DPUInventories:  []DPUInventory{},
			},
			wantName:   "testswitch",
			wantSerial: "sn101",
			wantErr:    "SmartSwitch namespace is empty",
		},
		{
			name:       "Nil Status",
			setup:      func() {},
			fields:     nil,
			wantName:   "testswitch",
			wantSerial: "",
			wantErr:    "SmartSwitch status is nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tc.setup()
			namespace := "default"
			if tc.name == "Nil Namespace" {
				namespace = ""
			}
			switchName := "testswitch"
			if tc.name == "Nil Name" {
				switchName = ""
			}
			obj, err := GetSmartSwitchInventory(switchName, namespace, tc.fields)
			if tc.wantErr == "" {
				require.NoError(t, err)
				require.Equal(t, tc.wantName, obj.Name)
				require.Equal(t, tc.wantSerial, obj.Status.SerialNumber)
			} else {
				require.EqualError(t, err, tc.wantErr)
			}
		})
	}
}
