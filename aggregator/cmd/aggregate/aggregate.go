// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package aggregate

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"

	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/spf13/cobra"

	"github.com/isovalent/hubble-fgs/pkg/model"
)

var queue = make(chan *v1alpha.ApplicationModelEvent, 100)
var mergedModel = &v1alpha.ApplicationModel{}
var mergedModelMutex sync.Mutex

func getCurrentModelJSON() ([]byte, error) {
	mergedModelMutex.Lock()
	defer mergedModelMutex.Unlock()
	mergedModelEvent := &v1alpha.ApplicationModelEvent{
		ApplicationModel: mergedModel,
	}
	b, err := mergedModelEvent.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return b, nil
}

func squash() {
	for {
		m := <-queue
		mergedModelMutex.Lock()
		mergedModel = model.Merge(mergedModel, m.GetApplicationModel())
		mergedModelMutex.Unlock()
	}
}

func handleJSONLines(w http.ResponseWriter, r *http.Request) {
	reader := bufio.NewReader(r.Body)
	for {
		b, err := reader.ReadBytes('\n')
		if err != nil {
			if !errors.Is(err, io.EOF) {
				http.Error(w, fmt.Sprintf("Invalid input: %s", err), http.StatusBadRequest)
			}
			return
		}
		ev := v1alpha.ApplicationModelEvent{}
		err = ev.UnmarshalJSON(b)
		if err != nil {
			continue
		}
		queue <- &ev
	}
}

func handleGet(w http.ResponseWriter, _ *http.Request) {
	modelJSON, err := getCurrentModelJSON()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to get current model: %s", err), http.StatusInternalServerError)
		return
	}
	w.Write(modelJSON)
}

func aggregate(_ *cobra.Command, _ []string) {
	handler := http.NewServeMux()
	handler.HandleFunc("POST /", handleJSONLines)
	handler.HandleFunc("GET /", handleGet)
	go squash()
	log.Fatal(http.ListenAndServe(":8080", handler))
}

func New() *cobra.Command {
	return &cobra.Command{
		Use: "aggregate",
		Run: aggregate,
	}
}
