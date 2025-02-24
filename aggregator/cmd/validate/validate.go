// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package validate

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/isovalent/hubble-fgs/pkg/model/checker"
	"github.com/isovalent/ipa/application_model/v1alpha"
	"github.com/spf13/cobra"
)

var (
	aggregatorURL    string
	validationYAML   string
	interval         time.Duration
	failureThreshold int
)

func getApplicationModel() (*v1alpha.ApplicationModelEvent, error) {
	ev := v1alpha.ApplicationModelEvent{}
	resp, err := http.Get(aggregatorURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if err := ev.UnmarshalJSON(body); err != nil {
		return nil, err
	}
	return &ev, nil
}

func validateApplicationModel(chk *checker.ApplicationModelChecker, validationYAML string) (checker.ApplicationCheckerResult, error) {
	appModel, err := getApplicationModel()
	if err != nil {
		return &checker.ResultFail{}, err
	}
	return chk.CheckApplicationModelYAML(context.Background(), appModel, validationYAML)
}

func validate(_ *cobra.Command, _ []string) error {
	failureCount := 0
	chk, err := checker.NewApplicationModelChecker()
	if err != nil {
		return err
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for range ticker.C {
		res, err := validateApplicationModel(chk, validationYAML)
		if err != nil || !res.Ok() {
			failureCount++
		} else {
			failureCount = 0
		}
		if failureCount >= failureThreshold {
			break
		}
	}
	return fmt.Errorf("exceeded failure threshold of %d", failureThreshold)
}

func New() *cobra.Command {
	cmd := cobra.Command{
		Use:  "validate",
		RunE: validate,
	}
	cmd.Flags().StringVar(&aggregatorURL, "aggregator-url", "http://tetragon-aggregator.tetragon.svc.cluster.local:8080/", "URL of the aggregator to validate")
	cmd.Flags().StringVar(&validationYAML, "validation-yaml", "/etc/tetragon/validation.yaml", "Path to the validation YAML file")
	cmd.Flags().DurationVar(&interval, "interval", 10*time.Second, "Interval between validations")
	cmd.Flags().IntVar(&failureThreshold, "failure-threshold", 10, "Number of consecutive failures to tolerate before exiting")
	return &cmd
}
