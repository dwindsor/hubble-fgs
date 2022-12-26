package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v2"
)

type confInput struct {
	path    string
	dropIn  bool
	write   bool // If set we write options to file/directories even if empty
	options map[string]interface{}
}

type testCase struct {
	description     string
	confs           []confInput
	expectedOptions map[string]interface{} // The expected Options after parsing all the above
}

var (
	globalTestIndex = 0

	testCases = []testCase{
		{
			description: "Test n0 Default configuration",
			// expected options: default options nothing changes
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "/var/lib/hubble-fgs/",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n1 Reset empty Drop-in /usr/lib/hubble-fgs/hubble-fgs.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside /usr/lib/hubble-fgs/hubble-fgs.conf.d/ directory
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true, // write empty values
					options: map[string]interface{}{
						keyConfigDir:       "",
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n2 Drop-in /usr/lib/hubble-fgs/hubble-fgs.conf.d/",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "/var/log/hubble-fgs.log_0",
				keyHubbleLib:       "/usr/lib/hubble-fgs/bpf/_0",
				keyBTF:             "/sys/kernel/btf/vmlinux-usr-lib_0",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_0",
						keyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n3 Reset empty Drop-in /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/ directory
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true, // write empty values
					options: map[string]interface{}{
						keyConfigDir:       "",
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n4 Drop-in /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "/var/log/hubble-fgs.log_1",
				keyHubbleLib:       "/usr/local/lib/hubble-fgs/bpf/_1",
				keyBTF:             "/sys/kernel/btf/vmlinux-usr-local-lib_1",
				keyVerbosity:       1,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_0",
						keyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      0,
						keyEventQueueSize: uint(0),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_1",
						keyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      1,
						keyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n5 Reset empty in /etc/hubble-fgs/hubble-fgs.yaml",
			// expected options: all zeroed / cleared values
			// As we write empty /etc/hubble-fgs/hubble-fgs.yaml file
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_0",
						keyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      1,
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_1",
						keyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      2,
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true, // write empty values
					options: map[string]interface{}{
						keyConfigDir:       "",
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n6 Partial update in /etc/hubble-fgs/hubble-fgs.yaml",
			// expected options: partial update
			// As we write /etc/hubble-fgs/hubble-fgs.yaml file
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "/var/lib/hubble-fgs/",
				keyBTF:             "/sys/kernel/btf/vmlinux",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true, // write values
					// Partial update only btf
					options: map[string]interface{}{
						keyBTF: "/sys/kernel/btf/vmlinux",
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			// Retest default values, assert our testing logic
			description: "Test n7 Re-test default values",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "/var/lib/hubble-fgs/",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n8 /etc/hubble-fgs/hubble-fgs.yaml",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "/var/run/hubble-fgs/hubble-fgs.log_2",
				keyHubbleLib:       "/var/lib/hubble-fgs/bpf/_2",
				keyBTF:             "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
				keyVerbosity:       2,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: true,
				keyEventQueueSize:  uint(20000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_0",
						keyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      0,
						keyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_1",
						keyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      1,
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "/var/run/hubble-fgs/hubble-fgs.log_2",
						keyHubbleLib:       "/var/lib/hubble-fgs/bpf/_2",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						keyVerbosity:       2,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: true,
						keyEventQueueSize:  uint(20000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n9 Reset empty Drop-in /etc/hubble-fgs/hubble-fgs.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside /etc/hubble-fgs/hubble-fgs.conf.d/ directory
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "",
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n10 Drop-in /etc/hubble-fgs/hubble-fgs.conf.d/",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "",
				keyExportFilename:  "/var/log/hubble-fgs.log_3",
				keyHubbleLib:       "/var/lib/hubble-fgs/_3",
				keyBTF:             "/sys/kernel/btf/vmlinux-etc_3",
				keyVerbosity:       3,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(30000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_0",
						keyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      0,
						keyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_1",
						keyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      1,
						keyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "/var/run/hubble-fgs/hubble-fgs.log_2",
						keyHubbleLib:       "/var/lib/hubble-fgs/bpf/_2",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						keyVerbosity:       2,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: true,
						keyEventQueueSize:  uint(20000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "/var/log/hubble-fgs.log_3",
						keyHubbleLib:       "/var/lib/hubble-fgs/_3",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc_3",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // config-dir
					path:   "",
					dropIn: true,
					write:  false,
				},
			},
		},
		{
			description: "Test n11 Reset empty Drop-in --config-dir /usr/lib/hubble-fgs",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "/etc/hubble-fgs/usr.lib.k8s.conf.d",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/usr.lib.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
			},
		},
		{
			description: "Test n12 Reset empty Drop-in --config-dir /usr/local/lib/hubble-fgs",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/usr.local.lib.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
			},
		},
		{
			description: "Test n13 Reset empty Drop-in --config-dir /etc/hubble-fgs/hubble-fgs.yaml",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
			},
		},
		{
			description: "Test n14 Reset empty Drop-in --config-dir /etc/hubble-fgs/hubble-fgs.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
				keyExportFilename:  "",
				keyHubbleLib:       "",
				keyBTF:             "",
				keyVerbosity:       0,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
						keyVerbosity:       3,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "",
						keyHubbleLib:       "",
						keyBTF:             "",
						keyVerbosity:       0,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(0),
					},
				},
			},
		},
		{
			description: "Test n15 Drop-in --config-dir from /etc/hubble-fgs/hubble-fgs.yaml",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
				keyExportFilename:  "/var/log/hubble-fgs.log_4",
				keyHubbleLib:       "/var/lib/hubble-fgs/_4",
				keyBTF:             "/sys/kernel/btf/vmlinux-etc_4",
				keyVerbosity:       4,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(40000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_0",
						keyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      0,
						keyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_1",
						keyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      1,
						keyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						keyExportFilename:  "/var/run/hubble-fgs/hubble-fgs.log_2",
						keyHubbleLib:       "/var/lib/hubble-fgs/bpf/_2",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						keyVerbosity:       2,
						keyEnableCiliumAPI: true,
						keyEnableK8sAPI:    true,
						keyEventQueueSize:  uint(20000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "/var/log/hubble-fgs.log_3",
						keyHubbleLib:       "/var/lib/hubble-fgs/_3",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc_3",
						keyVerbosity:       3,
						keyEnableCiliumAPI: true,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "/var/log/hubble-fgs.log_4",
						keyHubbleLib:       "/var/lib/hubble-fgs/_4",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc_4",
						keyVerbosity:       4,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(40000),
					},
				},
			},
		},
		{
			description: "Test n16 Drop-in --config-dir from /etc/hubble-fgs/hubble-fgs.conf.d/",
			expectedOptions: map[string]interface{}{
				keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
				keyExportFilename:  "/var/log/hubble-fgs.log_4",
				keyHubbleLib:       "/var/lib/hubble-fgs/_4",
				keyBTF:             "/sys/kernel/btf/vmlinux-etc_4",
				keyVerbosity:       4,
				keyEnableK8sAPI:    false,
				keyEnableCiliumAPI: false,
				keyEventQueueSize:  uint(40000),
			},
			confs: []confInput{
				{ // /usr/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_0",
						keyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						keyVerbosity:      0,
						keyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/hubble-fgs/hubble-fgs.conf.d/
					path:   "/usr/local/lib/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename: "/var/log/hubble-fgs.log_1",
						keyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						keyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						keyVerbosity:      1,
						keyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						keyExportFilename:  "/var/run/hubble-fgs/hubble-fgs.log_2",
						keyHubbleLib:       "/var/lib/hubble-fgs/bpf/_2",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						keyVerbosity:       2,
						keyEnableCiliumAPI: true,
						keyEnableK8sAPI:    true,
						keyEventQueueSize:  uint(20000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyConfigDir:       "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
						keyExportFilename:  "/var/log/hubble-fgs.log_3",
						keyHubbleLib:       "/var/lib/hubble-fgs/_3",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc_3",
						keyVerbosity:       3,
						keyEnableCiliumAPI: true,
						keyEventQueueSize:  uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						keyExportFilename:  "/var/log/hubble-fgs.log_4",
						keyHubbleLib:       "/var/lib/hubble-fgs/_4",
						keyBTF:             "/sys/kernel/btf/vmlinux-etc_4",
						keyVerbosity:       4,
						keyEnableK8sAPI:    false,
						keyEnableCiliumAPI: false,
						keyEventQueueSize:  uint(40000),
					},
				},
			},
		},
	}
)

func writeDropInConf(t *testing.T, testPath string, fullDir string, options map[string]interface{}) error {
	for k, v := range options {
		data := []byte(fmt.Sprint(v))
		file := filepath.Join(fullDir, k)
		err := os.WriteFile(file, data, 0644)
		if err != nil {
			return fmt.Errorf("failed to write %s: %v", file, err)
		}
	}

	return nil
}

func setupConfig(t *testing.T, testPath string, test testCase) error {

	// Patch expected config-dir path with test path prefix
	c := testCases[globalTestIndex]
	val, ok := c.expectedOptions["config-dir"]
	if ok && val != "" {
		testCases[globalTestIndex].expectedOptions["config-dir"] = filepath.Join(testPath, fmt.Sprint(val))
	}

	for _, c := range test.confs {
		if c.path == "" {
			continue
		}

		// Patch input config-dir path with test path prefix
		val, ok := c.options["config-dir"]
		if ok && val != "" {
			c.options["config-dir"] = filepath.Join(testPath, fmt.Sprint(val))
		}

		if c.dropIn == true {
			err := os.MkdirAll(filepath.Join(testPath, c.path), 0755)
			if err != nil {
				return err
			}

			if c.write {
				err = writeDropInConf(t, testPath, filepath.Join(testPath, c.path), c.options)
				if err != nil {
					return err
				}
			}

		} else {
			file := filepath.Join(testPath, c.path)
			err := os.MkdirAll(filepath.Dir(file), 0755)
			if err != nil {
				return err
			}

			if c.write {
				data, err := yaml.Marshal(&c.options)
				if err != nil {
					return err
				}

				err = os.WriteFile(file, data, 0644)
				if err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func cleanupConfig(t *testing.T, root string, test testCase) {
	for _, c := range test.confs {
		if c.path != "" {
			os.RemoveAll(filepath.Join(root, c.path))
		}
	}
}

func runTestCases(t *testing.T) {
	testDir := t.TempDir()

	c := testCases[globalTestIndex]

	err := setupConfig(t, testDir, c)
	require.NoErrorf(t, err, "failed at test case %s", c.description)

	defaultConfYamlFile := filepath.Join(testDir, adminFgsConfDir)
	defaultConfDropIn := filepath.Join(testDir, adminFgsConfDropIn)
	packageConfDropIns := make([]string, 0)
	for _, c := range packageFgsConfDropIns {
		packageConfDropIns = append(packageConfDropIns, filepath.Join(testDir, c))
	}
	log.Infof("Test %s index %d dumping settings before: %+v", c.description, globalTestIndex, viper.AllSettings())
	readConfigSettings(defaultConfYamlFile, defaultConfDropIn, packageConfDropIns)
	log.Infof("Test %s index %d expected settings: %+v", c.description, globalTestIndex, c.expectedOptions)
	log.Infof("Test %s index %d dumping settings after: %+v", c.description, globalTestIndex, viper.AllSettings())

	for opt, v := range c.expectedOptions {
		switch expected := v.(type) {
		case int:
			actual := viper.GetInt(opt)
			require.EqualValuesf(t, expected, actual, "failed to match int option '%s' at test %s", opt, c.description)
		case uint:
			actual := viper.GetUint(opt)
			require.EqualValuesf(t, expected, actual, "failed to match uint option '%s' at test %s", opt, c.description)
		case string:
			actual := viper.GetString(opt)
			require.EqualValuesf(t, expected, actual, "failed to match string option '%s' at test %s", opt, c.description)
		case bool:
			actual := viper.GetBool(opt)
			require.EqualValuesf(t, expected, actual, "failed to match bool option '%s' at test %s", opt, c.description)
		}
	}

	cleanupConfig(t, testDir, c)
}

func TestReadConfigSettings(t *testing.T) {
	for i, c := range testCases {
		globalTestIndex = i
		rootCmd := &cobra.Command{
			Use:   "testing-only",
			Short: "Perform read configuration tests",
			Run: func(cmd *cobra.Command, args []string) {
				runTestCases(t)
			},
		}

		flags := rootCmd.PersistentFlags()
		flags.String(keyConfigDir, "", "Configuration directory that contains a file for each option")
		flags.String(keyHubbleLib, "/var/lib/hubble-fgs/", "Location of hubble-fgs libs (btf and bpf files)")
		flags.String(keyBTF, "", "Location of btf")
		flags.String(keyExportFilename, "", "Filename for JSON export. Disabled by default")
		flags.Int(keyVerbosity, 0, "set verbosity level for eBPF verifier dumps. Pass 0 for silent, 1 for truncated logs, 2 for a full dump")
		flags.Bool(keyEnableK8sAPI, false, "Access Kubernetes API to associate hubble-fgs events with Kubernetes pods")
		flags.Bool(keyEnableCiliumAPI, false, "Access Cilium API to associate hubble-fgs events with Cilium endpoints and DNS cache")
		flags.Uint(keyEventQueueSize, 10000, "Set the size of the internal event queue.")
		viper.BindPFlags(flags)
		t.Run(c.description, func(t *testing.T) {
			rootCmd.Execute()
		})
		viper.Reset()
	}
}
