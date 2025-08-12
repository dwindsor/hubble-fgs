package tetragon

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/tetragon/pkg/defaults"
	opt "github.com/cilium/tetragon/pkg/option"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/isovalent/hubble-fgs/pkg/option"
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
	testGlobalIndex = 0

	testCasesHubbleFgs = []testCase{
		{
			description: "Test n0 Default configuration",
			// expected options: default options nothing changes
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "/var/lib/tetragon/",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
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
			description: "Test n1 Reset empty Drop-in /usr/lib/tetragon/tetragon.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside /usr/lib/tetragon/tetragon.conf.d/ directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true, // write empty values
					options: map[string]interface{}{
						opt.KeyConfigDir:          "",
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
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
			description: "Test n2 Drop-in /usr/lib/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "/var/log/tetragon.log_0",
				opt.KeyHubbleLib:          "/usr/lib/hubble-fgs/bpf/_0",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-usr-lib_0",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
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
			description: "Test n3 Reset empty Drop-in /usr/local/lib/tetragon/tetragon.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside /usr/local/lib/tetragon/tetragon.conf.d/ directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true, // write empty values
					options: map[string]interface{}{
						opt.KeyConfigDir:          "",
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
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
			description: "Test n4 Drop-in /usr/local/lib/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "/var/log/tetragon.log_1",
				opt.KeyHubbleLib:          "/usr/local/lib/hubble-fgs/bpf/_1",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-usr-local-lib_1",
				opt.KeyVerbosity:          1,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(0),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
						opt.KeyEventQueueSize: uint(10000),
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
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      1,
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      2,
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true, // write empty values
					options: map[string]interface{}{
						opt.KeyConfigDir:          "",
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
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
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "/var/lib/tetragon/",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true, // write values
					// Partial update only btf
					options: map[string]interface{}{
						opt.KeyBTF: "/sys/kernel/btf/vmlinux",
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
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "/var/lib/tetragon/",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
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
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
				opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
				opt.KeyVerbosity:          2,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: true,
				opt.KeyEventQueueSize:     uint(20000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
						opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						opt.KeyVerbosity:          2,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEventQueueSize:     uint(20000),
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
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
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
						opt.KeyConfigDir:          "",
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
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
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "/var/log/tetragon.log_3",
				opt.KeyHubbleLib:          "/var/lib/tetragon/_3",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_3",
				opt.KeyVerbosity:          3,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(30000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
						opt.KeyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
						opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						opt.KeyVerbosity:          2,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEventQueueSize:     uint(20000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/log/tetragon.log_3",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_3",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_3",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
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
				opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/usr.lib.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
			},
		},
		{
			description: "Test n12 Reset empty Drop-in --config-dir /usr/local/lib/hubble-fgs",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/usr.local.lib.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
			},
		},
		{
			description: "Test n13 Reset empty Drop-in --config-dir /etc/hubble-fgs/hubble-fgs.yaml",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
			},
		},
		{
			description: "Test n14 Reset empty Drop-in --config-dir /etc/hubble-fgs/hubble-fgs.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
			},
		},
		{
			description: "Test n15 Drop-in --config-dir from /etc/hubble-fgs/hubble-fgs.yaml",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
				opt.KeyExportFilename:     "/var/log/tetragon.log_4",
				opt.KeyHubbleLib:          "/var/lib/tetragon/_4",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_4",
				opt.KeyVerbosity:          4,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(40000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
						opt.KeyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
						opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						opt.KeyVerbosity:          2,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEnableK8sAPI:       true,
						opt.KeyEventQueueSize:     uint(20000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/log/tetragon.log_3",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_3",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_3",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/log/tetragon.log_4",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_4",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_4",
						opt.KeyVerbosity:          4,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(40000),
					},
				},
			},
		},
		{
			description: "Test n16 Drop-in --config-dir from /etc/hubble-fgs/hubble-fgs.conf.d/",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
				opt.KeyExportFilename:     "/var/log/tetragon.log_4",
				opt.KeyHubbleLib:          "/var/lib/tetragon/_4",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_4",
				opt.KeyVerbosity:          4,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(40000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
						opt.KeyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.yaml
					path:   "/etc/hubble-fgs/hubble-fgs.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
						opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						opt.KeyVerbosity:          2,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEnableK8sAPI:       true,
						opt.KeyEventQueueSize:     uint(20000),
					},
				},
				{ // /etc/hubble-fgs/hubble-fgs.conf.d/
					path:   "/etc/hubble-fgs/hubble-fgs.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
						opt.KeyExportFilename:     "/var/log/tetragon.log_3",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_3",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_3",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/log/tetragon.log_4",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_4",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_4",
						opt.KeyVerbosity:          4,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(40000),
					},
				},
			},
		},
	}

	testCasesTetragon = []testCase{
		{
			description: "Test n0 Default configuration",
			// expected options: default options nothing changes
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "/var/lib/tetragon/",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
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
			description: "Test n1 Reset empty Drop-in /usr/lib/tetragon/tetragon.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside /usr/lib/tetragon/tetragon.conf.d/ directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true, // write empty values
					options: map[string]interface{}{
						opt.KeyConfigDir:          "",
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
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
			description: "Test n2 Drop-in /usr/lib/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "/var/log/tetragon.log_0",
				opt.KeyHubbleLib:          "/usr/lib/hubble-fgs/bpf/_0",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-usr-lib_0",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
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
			description: "Test n3 Reset empty Drop-in /usr/local/lib/tetragon/tetragon.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside /usr/local/lib/tetragon/tetragon.conf.d/ directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true, // write empty values
					options: map[string]interface{}{
						opt.KeyConfigDir:          "",
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
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
			description: "Test n4 Drop-in /usr/local/lib/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "/var/log/tetragon.log_1",
				opt.KeyHubbleLib:          "/usr/local/lib/hubble-fgs/bpf/_1",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-usr-local-lib_1",
				opt.KeyVerbosity:          1,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(0),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
						opt.KeyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
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
			description: "Test n5 Reset empty in /etc/tetragon/tetragon.yaml",
			// expected options: all zeroed / cleared values
			// As we write empty /etc/hubble-fgs/hubble-fgs.yaml file
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      1,
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      2,
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true, // write empty values
					options: map[string]interface{}{
						opt.KeyConfigDir:          "",
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
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
			description: "Test n6 Partial update in /etc/tetragon/tetragon.yaml",
			// expected options: partial update
			// As we write /etc/hubble-fgs/hubble-fgs.yaml file
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "/var/lib/tetragon/",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true, // write values
					// Partial update only btf
					options: map[string]interface{}{
						opt.KeyBTF: "/sys/kernel/btf/vmlinux",
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
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
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "/var/lib/tetragon/",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(10000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "",
					dropIn: false,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
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
			description: "Test n8 /etc/tetragon/tetragon.yaml",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
				opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
				opt.KeyVerbosity:          2,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: true,
				opt.KeyEventQueueSize:     uint(20000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
						opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						opt.KeyVerbosity:          2,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEventQueueSize:     uint(20000),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
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
			description: "Test n9 Reset empty Drop-in /etc/tetragon/tetragon.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside /etc/hubble-fgs/hubble-fgs.conf.d/ directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  false,
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "",
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
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
			description: "Test n10 Drop-in /etc/tetragon/tetragon.conf.d/",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "",
				opt.KeyExportFilename:     "/var/log/tetragon.log_3",
				opt.KeyHubbleLib:          "/var/lib/tetragon/_3",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_3",
				opt.KeyVerbosity:          3,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(30000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
						opt.KeyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
						opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						opt.KeyVerbosity:          2,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEventQueueSize:     uint(20000),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/log/tetragon.log_3",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_3",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_3",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
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
				opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d//",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/usr.lib.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
			},
		},
		{
			description: "Test n12 Reset empty Drop-in --config-dir /usr/local/lib/hubble-fgs",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/usr.local.lib.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
			},
		},
		{
			description: "Test n13 Reset empty Drop-in --config-dir /etc/hubble-fgs/hubble-fgs.yaml",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
			},
		},
		{
			description: "Test n14 Reset empty Drop-in --config-dir /etc/hubble-fgs/hubble-fgs.conf.d/",
			// expected options: all zeroed / cleared values
			// As we write empty drop-ins inside --config-dir directory
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
				opt.KeyExportFilename:     "",
				opt.KeyHubbleLib:          "",
				opt.KeyBTF:                "",
				opt.KeyVerbosity:          0,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(0),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/usr.local.lib.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "",
						opt.KeyHubbleLib:          "",
						opt.KeyBTF:                "",
						opt.KeyVerbosity:          0,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(0),
					},
				},
			},
		},
		{
			description: "Test n15 Drop-in --config-dir from /etc/hubble-fgs/hubble-fgs.yaml",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
				opt.KeyExportFilename:     "/var/log/tetragon.log_4",
				opt.KeyHubbleLib:          "/var/lib/tetragon/_4",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_4",
				opt.KeyVerbosity:          4,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(40000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
						opt.KeyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
						opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						opt.KeyVerbosity:          2,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEnableK8sAPI:       true,
						opt.KeyEventQueueSize:     uint(20000),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/log/tetragon.log_3",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_3",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_3",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/log/tetragon.log_4",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_4",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_4",
						opt.KeyVerbosity:          4,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(40000),
					},
				},
			},
		},
		{
			description: "Test n16 Drop-in --config-dir from /etc/hubble-fgs/hubble-fgs.conf.d/",
			expectedOptions: map[string]interface{}{
				opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
				opt.KeyExportFilename:     "/var/log/tetragon.log_4",
				opt.KeyHubbleLib:          "/var/lib/tetragon/_4",
				opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_4",
				opt.KeyVerbosity:          4,
				opt.KeyEnableK8sAPI:       false,
				option.KeyEnableCiliumAPI: false,
				opt.KeyEventQueueSize:     uint(40000),
			},
			confs: []confInput{
				{ // /usr/lib/tetragon/tetragon.conf.d/
					path:   "/usr/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_0",
						opt.KeyHubbleLib:      "/usr/lib/hubble-fgs/bpf/_0",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-lib_0",
						opt.KeyVerbosity:      0,
						opt.KeyEventQueueSize: uint(5000),
					},
				},
				{ // /usr/local/lib/tetragon/tetragon.conf.d/
					path:   "/usr/local/lib/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename: "/var/log/tetragon.log_1",
						opt.KeyHubbleLib:      "/usr/local/lib/hubble-fgs/bpf/_1",
						opt.KeyBTF:            "/sys/kernel/btf/vmlinux-usr-local-lib_1",
						opt.KeyVerbosity:      1,
						opt.KeyEventQueueSize: uint(10000),
					},
				},
				{ // /etc/tetragon/tetragon.yaml
					path:   "/etc/tetragon/tetragon.yaml",
					dropIn: false,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.yaml.k8s.conf.d",
						opt.KeyExportFilename:     "/var/run/hubble-fgs/hubble-fgs.log_2",
						opt.KeyHubbleLib:          "/var/lib/tetragon/bpf/_2",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc-hubble-fgs.yaml_2",
						opt.KeyVerbosity:          2,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEnableK8sAPI:       true,
						opt.KeyEventQueueSize:     uint(20000),
					},
				},
				{ // /etc/tetragon/tetragon.conf.d/
					path:   "/etc/tetragon/tetragon.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyConfigDir:          "/etc/hubble-fgs/hubble-fgs.k8s.conf.d",
						opt.KeyExportFilename:     "/var/log/tetragon.log_3",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_3",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_3",
						opt.KeyVerbosity:          3,
						option.KeyEnableCiliumAPI: true,
						opt.KeyEventQueueSize:     uint(30000),
					},
				},
				{ // config-dir
					path:   "/etc/hubble-fgs/hubble-fgs.k8s.conf.d/",
					dropIn: true,
					write:  true,
					options: map[string]interface{}{
						opt.KeyExportFilename:     "/var/log/tetragon.log_4",
						opt.KeyHubbleLib:          "/var/lib/tetragon/_4",
						opt.KeyBTF:                "/sys/kernel/btf/vmlinux-etc_4",
						opt.KeyVerbosity:          4,
						opt.KeyEnableK8sAPI:       false,
						option.KeyEnableCiliumAPI: false,
						opt.KeyEventQueueSize:     uint(40000),
					},
				},
			},
		},
	}
)

func writeDropInConf(_ *testing.T, _ string, fullDir string, options map[string]interface{}) error {
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

func setupConfig(t *testing.T, testCases []testCase, testPath string, test testCase) error {

	// Patch expected config-dir path with test path prefix
	val, ok := test.expectedOptions["config-dir"]
	if ok && val != "" {
		testCases[testGlobalIndex].expectedOptions["config-dir"] = filepath.Join(testPath, fmt.Sprint(val))
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

func cleanupConfig(_ *testing.T, root string, test testCase) {
	for _, c := range test.confs {
		if c.path != "" {
			os.RemoveAll(filepath.Join(root, c.path))
		}
	}
}

func runTestCases(t *testing.T, newConf bool, testCases []testCase, confDir, confDropIn string) {
	testDir := t.TempDir()

	c := testCases[testGlobalIndex]

	err := setupConfig(t, testCases, testDir, c)
	require.NoErrorf(t, err, "failed at test case %s", c.description)

	defaultConfYamlFile := filepath.Join(testDir, confDir)
	defaultConfDropIn := filepath.Join(testDir, confDropIn)
	packageConfDropIns := make([]string, 0)
	for _, c := range packageTgConfDropIns {
		packageConfDropIns = append(packageConfDropIns, filepath.Join(testDir, c))
	}
	log.Info(fmt.Sprintf("Test %s index %d dumping settings before: %+v", c.description, testGlobalIndex, viper.AllSettings()))
	// use newConf as newEnv here
	readConfigSettings(newConf, newConf, defaultConfYamlFile, defaultConfDropIn, packageConfDropIns)
	log.Info(fmt.Sprintf("Test %s index %d expected settings: %+v", c.description, testGlobalIndex, c.expectedOptions))
	log.Info(fmt.Sprintf("Test %s index %d dumping settings after: %+v", c.description, testGlobalIndex, viper.AllSettings()))

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

func testReadConfigSettings(t *testing.T, newConf bool, testCases []testCase, confDir, confDropIn string) {
	testGlobalIndex = 0
	for i, c := range testCases {
		testGlobalIndex = i
		rootCmd := &cobra.Command{
			Use:   "testing-only",
			Short: "Perform read configuration tests including /etc/hubble-fgs/",
			Run: func(_ *cobra.Command, _ []string) {
				// Test old /etc/hubble-fgs directory
				runTestCases(t, newConf, testCases, confDir, confDropIn)
				// Test new /etc/tetragon directory
				//runTestCases(t, adminTgConfDir, adminTgConfDropIn)
			},
		}

		flags := rootCmd.PersistentFlags()
		flags.String(opt.KeyConfigDir, "", "Configuration directory that contains a file for each option")
		flags.String(opt.KeyHubbleLib, defaults.DefaultTetragonLib, "Location of hubble-fgs libs (btf and bpf files)")
		flags.String(opt.KeyBTF, "", "Location of btf")
		flags.String(opt.KeyExportFilename, "", "Filename for JSON export. Disabled by default")
		flags.Int(opt.KeyVerbosity, 0, "set verbosity level for eBPF verifier dumps. Pass 0 for silent, 1 for truncated logs, 2 for a full dump")
		flags.Bool(opt.KeyEnableK8sAPI, false, "Access Kubernetes API to associate hubble-fgs events with Kubernetes pods")
		flags.Bool(option.KeyEnableCiliumAPI, false, "Access Cilium API to associate hubble-fgs events with Cilium endpoints and DNS cache")
		flags.Uint(opt.KeyEventQueueSize, 10000, "Set the size of the internal event queue.")
		viper.BindPFlags(flags)
		t.Run(c.description, func(_ *testing.T) {
			rootCmd.Execute()
		})
		viper.Reset()
	}
}

func TestReadConfigSettingsHubbleFgs(t *testing.T) {
	testReadConfigSettings(t, false, testCasesHubbleFgs, oldAdminFgsConfDir, oldAdminFgsConfDropIn)
}

func TestReadConfigSettingsTetragon(t *testing.T) {
	testReadConfigSettings(t, true, testCasesTetragon, adminTgConfDir, adminTgConfDropIn)
}
