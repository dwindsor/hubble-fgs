// Copyright 2020 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package lrumetrics

import (
	"fmt"

	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	LruMapSize = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        "lru_in_use_gauge",
		Namespace:   consts.MetricsNamespace,
		Help:        "The total number of LRU in-use entries.",
		ConstLabels: nil,
	}, []string{"map", "total"})
)

func InitMetrics(registry *prometheus.Registry) {
	registry.MustRegister(LruMapSize)
}

// Get a new handle on LruMapSize for a given map name and capacity
func GetLruMapSize(mapName string, capacity int) prometheus.Gauge {
	return LruMapSize.WithLabelValues(mapName, fmt.Sprint(capacity))
}

// Set a new value for LruMapSize for a given map name and capacity
func LruMapSizeSet(mapName string, capacity int, len_ float64) {
	GetLruMapSize(mapName, capacity).Set(len_)
}
