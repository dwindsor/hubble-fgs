// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mock

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

//go:embed default.json
var defaultJSON []byte

// HandlerBuilder provides a fluent interface for building configured Handler instances.
type HandlerBuilder struct {
	tree        map[string]interface{}
	persistPath string
	getErrors   map[string]error
	setErrors   map[string]error
}

// NewHandlerBuilder creates a new builder initialized from the embedded default JSON tree.
func NewHandlerBuilder() *HandlerBuilder {
	var tree map[string]interface{}
	if err := json.Unmarshal(defaultJSON, &tree); err != nil {
		panic(fmt.Sprintf("mock: failed to parse default.json: %v", err))
	}
	return &HandlerBuilder{
		tree:      tree,
		getErrors: make(map[string]error),
		setErrors: make(map[string]error),
	}
}

// WithJSON replaces the builder's tree with the tree parsed from raw JSON bytes.
func (b *HandlerBuilder) WithJSON(raw []byte) *HandlerBuilder {
	var tree map[string]interface{}
	if err := json.Unmarshal(raw, &tree); err != nil {
		panic(fmt.Sprintf("mock: failed to parse JSON: %v", err))
	}
	b.tree = tree
	return b
}

// WithTree deep-merges subtree into the builder's tree.
// Maps are merged recursively; leaf values in subtree overwrite those in the current tree.
func (b *HandlerBuilder) WithTree(subtree map[string]interface{}) *HandlerBuilder {
	deepMerge(b.tree, subtree)
	return b
}

// WithPath sets a single leaf value at the given slash-separated normalized path.
// For example: WithPath("System/sas-items/globalpol-items/lbMode", "pinning")
func (b *HandlerBuilder) WithPath(path, value string) *HandlerBuilder {
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	cur := b.tree
	for i, part := range parts {
		if i == len(parts)-1 {
			cur[part] = value
		} else {
			if next, ok := cur[part].(map[string]interface{}); ok {
				cur = next
			} else {
				next = make(map[string]interface{})
				cur[part] = next
				cur = next
			}
		}
	}
	return b
}

// WithPersistPath sets the file path for persisting mock gNMI data across restarts.
func (b *HandlerBuilder) WithPersistPath(path string) *HandlerBuilder {
	b.persistPath = path
	return b
}

// WithGetError configures the mock to return an error for Get operations on the specified path.
func (b *HandlerBuilder) WithGetError(path string, err error) *HandlerBuilder {
	b.getErrors[path] = err
	return b
}

// WithSetError configures the mock to return an error for Set operations on the specified path.
func (b *HandlerBuilder) WithSetError(path string, err error) *HandlerBuilder {
	b.setErrors[path] = err
	return b
}

// Build creates the Handler. If a persist file exists it is used as the sole data
// source; otherwise the handler is initialized from the builder's tree.
// When a persistPath is configured, a transaction log is created at the same
// directory with the name "mock_gnmi.log", and a startup entry is written.
func (b *HandlerBuilder) Build() *Handler {
	h := &Handler{
		data:        make(map[string]interface{}),
		getErrors:   b.getErrors,
		setErrors:   b.setErrors,
		persistPath: b.persistPath,
	}
	if b.persistPath != "" {
		logPath := filepath.Join(filepath.Dir(b.persistPath), "mock_gnmi.log")
		h.txLog = NewTxLog(logPath)
		h.txLog.Log("startup", "", "", "")
	}
	if !h.loadPersisted() {
		for k, v := range TreeToFlat(b.tree) {
			h.data[k] = v
		}
	}
	return h
}

// --- Tree helper types and functions ---

// VRFEntry is a lightweight VRF descriptor for use with VRFTree.
type VRFEntry struct {
	Name     string
	Affinity uint16
}

// HAPeer is a lightweight HA peer descriptor for use with HATree.
type HAPeer struct {
	IP       string
	Priority int
	State    string
}

// DPUTree returns a tree fragment for N DPUs with sequential module numbers and IPs.
// Merging this into a builder via WithTree replaces any existing DPU configuration.
func DPUTree(count int) map[string]interface{} {
	instItems := make(map[string]interface{})
	for i := 0; i < count; i++ {
		key := fmt.Sprintf("Inst-list[moduleNum=%d]", i+1)
		instItems[key] = map[string]interface{}{
			"ext-items": map[string]interface{}{
				"ip":        fmt.Sprintf("192.168.1.%d", i+1),
				"state":     "online",
				"mainFwVer": "1.0.0",
			},
		}
	}
	return map[string]interface{}{
		"System": map[string]interface{}{
			"sas-items": map[string]interface{}{
				"dpu-items": map[string]interface{}{
					"ext-items": map[string]interface{}{
						"numDpus":   count,
						"initState": "inventory-done",
					},
					"inst-items": instItems,
				},
			},
		},
	}
}

// VRFTree returns a tree fragment for the given VRFs, suitable for merging with WithTree.
// Each subsequent call to WithTree(VRFTree(...)) adds VRFs without overwriting existing ones.
func VRFTree(vrfs ...VRFEntry) map[string]interface{} {
	globalInst := make(map[string]interface{})
	domList := make(map[string]interface{})
	for _, vrf := range vrfs {
		globalInst[fmt.Sprintf("Inst-list[name=%s]", vrf.Name)] = map[string]interface{}{
			"name": vrf.Name,
		}
		domList[fmt.Sprintf("Dom-list[name=%s]", vrf.Name)] = map[string]interface{}{
			"name":     vrf.Name,
			"affinity": int(vrf.Affinity),
		}
	}
	return map[string]interface{}{
		"System": map[string]interface{}{
			"inst-items": globalInst,
			"sas-items": map[string]interface{}{
				"svc-items": map[string]interface{}{
					"svcinst-items": map[string]interface{}{
						"SvcInstance-list[name=hypershield]": map[string]interface{}{
							"fwpolicy-items": map[string]interface{}{
								"ipvrf-items": map[string]interface{}{
									"dom-items": domList,
								},
							},
						},
					},
				},
			},
		},
	}
}

// VLANTree returns a tree fragment for the given VLAN IDs (e.g., "100", "200"),
// suitable for merging with WithTree.
func VLANTree(ids ...string) map[string]interface{} {
	bdList := make(map[string]interface{})
	vlanList := make(map[string]interface{})
	for _, id := range ids {
		fabEncap := fmt.Sprintf("vxlan-%s", id)
		bdList[fmt.Sprintf("BD-list[fabEncap=%s]", fabEncap)] = map[string]interface{}{
			"fabEncap": fabEncap,
		}
		vlanList[fmt.Sprintf("Vlan-list[vlanId=%s]", id)] = map[string]interface{}{
			"vlanId":   id,
			"affinity": 0,
		}
	}
	return map[string]interface{}{
		"System": map[string]interface{}{
			"bd-items": map[string]interface{}{
				"bd-items": bdList,
			},
			"sas-items": map[string]interface{}{
				"svc-items": map[string]interface{}{
					"svcinst-items": map[string]interface{}{
						"SvcInstance-list[name=hypershield]": map[string]interface{}{
							"fwpolicy-items": map[string]interface{}{
								"bd-items": map[string]interface{}{
									"vlan-items": vlanList,
								},
							},
						},
					},
				},
			},
		},
	}
}

// HATree returns a tree fragment for HA configuration, suitable for merging with WithTree.
// When enabled is true, adminState is set to "enabled"; when false, "disabled".
// sourceIP sets the HA source interface address. peers configures HA peers as a JSON blob.
func HATree(enabled bool, sourceIP string, peers ...HAPeer) map[string]interface{} {
	adminState := "disabled"
	if enabled {
		adminState = "enabled"
	}

	haItems := map[string]interface{}{
		"adminState": adminState,
	}
	if len(peers) > 0 {
		peerList := make([]interface{}, 0, len(peers))
		for _, p := range peers {
			peerList = append(peerList, map[string]interface{}{
				"ipAddr":        p.IP,
				"priority":      p.Priority,
				"state":         p.State,
				"ipConfigState": "success",
			})
		}
		peerJSON, _ := json.Marshal(peerList)
		haItems["peer-items"] = map[string]interface{}{
			"HaPeer-list": string(peerJSON),
		}
	}

	tree := map[string]interface{}{
		"System": map[string]interface{}{
			"sas-items": map[string]interface{}{
				"svc-items": map[string]interface{}{
					"svcinst-items": map[string]interface{}{
						"SvcInstance-list[name=hypershield]": map[string]interface{}{
							"ha-items": haItems,
						},
					},
				},
			},
		},
	}
	if sourceIP != "" {
		agentItems := map[string]interface{}{
			"SasAgent-list[svcName=hypershield]": map[string]interface{}{
				"agentHaSrcIntfAddr": sourceIP,
			},
		}
		stateItems := tree["System"].(map[string]interface{})["sas-items"].(map[string]interface{})
		stateItems["state-items"] = map[string]interface{}{
			"agent-items": agentItems,
		}
	}
	return tree
}

// deepMerge recursively merges src into dst.
// Maps are merged; all other values in src overwrite those in dst.
func deepMerge(dst, src map[string]interface{}) {
	for k, srcVal := range src {
		if srcMap, ok := srcVal.(map[string]interface{}); ok {
			if dstMap, ok := dst[k].(map[string]interface{}); ok {
				deepMerge(dstMap, srcMap)
			} else {
				cloned := make(map[string]interface{}, len(srcMap))
				for sk, sv := range srcMap {
					cloned[sk] = sv
				}
				dst[k] = cloned
			}
		} else {
			dst[k] = srcVal
		}
	}
}
