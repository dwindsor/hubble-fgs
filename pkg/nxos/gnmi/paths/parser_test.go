// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package paths

import (
	"testing"
)

func TestPathMatches(t *testing.T) {
	tests := []struct {
		name             string
		notificationPath string
		subscriptionPath string
		want             bool
	}{
		{
			name:             "exact match leaf path",
			notificationPath: "System/inst-items/Inst-list[name=default]/connToken",
			subscriptionPath: "device:/System/inst-items/Inst-list/connToken",
			want:             true,
		},
		{
			name:             "exact match no origin no selectors",
			notificationPath: "System/inst-items/Inst-list/connToken",
			subscriptionPath: "System/inst-items/Inst-list/connToken",
			want:             true,
		},
		{
			name:             "exact match with origin on both",
			notificationPath: "device:/System/inst-items/Inst-list/connToken",
			subscriptionPath: "device:/System/inst-items/Inst-list/connToken",
			want:             true,
		},
		{
			name:             "notification is child of subscription - no match",
			notificationPath: "System/inst-items/Inst-list[name=default]/dom-items/Dom-list[name=foo]",
			subscriptionPath: "device:/System/inst-items/Inst-list",
			want:             false,
		},
		{
			name:             "partial name overlap - no match",
			notificationPath: "System/inst-items/Inst-list-extra/name",
			subscriptionPath: "device:/System/inst-items/Inst-list/name",
			want:             false,
		},
		{
			name:             "different paths",
			notificationPath: "System/other-items/name",
			subscriptionPath: "device:/System/inst-items/name",
			want:             false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PathMatches(tt.notificationPath, tt.subscriptionPath)
			if got != tt.want {
				t.Errorf("PathMatches(%q, %q) = %v, want %v",
					tt.notificationPath, tt.subscriptionPath, got, tt.want)
			}
		})
	}
}

func TestPathMatchesPrefix(t *testing.T) {
	tests := []struct {
		name             string
		notificationPath string
		subscriptionPath string
		want             bool
	}{
		{
			name:             "notification is child of subscription container",
			notificationPath: "System/inst-items/Inst-list[name=default]/dom-items/Dom-list[name=foo]",
			subscriptionPath: "device:/System/inst-items/Inst-list",
			want:             true,
		},
		{
			name:             "notification matches subscription exactly",
			notificationPath: "System/inst-items/Inst-list[name=default]",
			subscriptionPath: "device:/System/inst-items/Inst-list",
			want:             true,
		},
		{
			name:             "leaf path prefix match",
			notificationPath: "System/inst-items/Inst-list[name=default]/connToken",
			subscriptionPath: "device:/System/inst-items/Inst-list/connToken",
			want:             true,
		},
		{
			name:             "different paths",
			notificationPath: "System/other-items/name",
			subscriptionPath: "device:/System/inst-items/Inst-list",
			want:             false,
		},
		{
			name:             "svc fw policy child delete notification",
			notificationPath: "System/svcCont/svcCFwPol-items/SvcCFwPol-list[name=foo]/rule-items",
			subscriptionPath: "device:/System/svcCont/svcCFwPol-items/SvcCFwPol-list",
			want:             true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := PathMatchesPrefix(tt.notificationPath, tt.subscriptionPath)
			if got != tt.want {
				t.Errorf("PathMatchesPrefix(%q, %q) = %v, want %v",
					tt.notificationPath, tt.subscriptionPath, got, tt.want)
			}
		})
	}
}

func TestExtractDPUModuleNum(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantNum int
		wantOk  bool
	}{
		{
			name:    "valid moduleNum",
			path:    "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=1]/ext-items/ip",
			wantNum: 1,
			wantOk:  true,
		},
		{
			name:    "multi-digit moduleNum",
			path:    "device:/System/sas-items/dpu-items/inst-items/Inst-list[moduleNum=12]/ext-items/state",
			wantNum: 12,
			wantOk:  true,
		},
		{
			name:    "no moduleNum selector",
			path:    "device:/System/sas-items/dpu-items/inst-items/Inst-list/ext-items/ip",
			wantNum: 0,
			wantOk:  false,
		},
		{
			name:    "name selector instead of moduleNum",
			path:    "device:/System/inst-items/Inst-list[name=default]/dom-items",
			wantNum: 0,
			wantOk:  false,
		},
		{
			name:    "empty path",
			path:    "",
			wantNum: 0,
			wantOk:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNum, gotOk := ExtractDPUModuleNum(tt.path)
			if gotNum != tt.wantNum || gotOk != tt.wantOk {
				t.Errorf("ExtractDPUModuleNum(%q) = (%d, %v), want (%d, %v)",
					tt.path, gotNum, gotOk, tt.wantNum, tt.wantOk)
			}
		})
	}
}
