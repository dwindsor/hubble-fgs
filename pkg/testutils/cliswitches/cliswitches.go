// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package cliswitches

import (
	"fmt"
	"testing"
	"time"

	enterpriseOption "github.com/isovalent/hubble-fgs/pkg/option"
)

type SwitchSettings struct {
	KeyPtr   any
	Value    any
	OldValue any
}

func setSwitchesInternal(switches []SwitchSettings, revert bool) ([]SwitchSettings, error) {
	r := []SwitchSettings{}
	for _, s := range switches {
		switch v := s.KeyPtr.(type) {
		case (*bool):
			if !revert {
				s.OldValue = *v
				*v = s.Value.(bool)
			} else {
				*v = s.OldValue.(bool)
			}
		case (*int):
			if !revert {
				s.OldValue = *v
				*v = s.Value.(int)
			} else {
				*v = s.OldValue.(int)
			}
		case (*[]int):
			if !revert {
				s.OldValue = *v
				*v = s.Value.([]int)
			} else {
				*v = s.OldValue.([]int)
			}
		case (*float64):
			if !revert {
				s.OldValue = *v
				*v = s.Value.(float64)
			} else {
				*v = s.OldValue.(float64)
			}
		case (*time.Duration):
			if !revert {
				s.OldValue = *v
				*v = s.Value.(time.Duration)
			} else {
				*v = s.OldValue.(time.Duration)
			}
		case (*enterpriseOption.MulticastAppID):
			if !revert {
				s.OldValue = *v
				*v = s.Value.(enterpriseOption.MulticastAppID)
			} else {
				*v = s.OldValue.(enterpriseOption.MulticastAppID)
			}
		default:
			return []SwitchSettings{}, fmt.Errorf("type %T is not handled in setSwitchesInternal", v)
		}
		r = append(r, s)
	}
	return r, nil
}

// SetConfigFromSwitches() sets the CLI switch config specified, and returns an
// updated spec that should be used to revert the settings at the end of the test.
// Use SetSwitches() to automate this.
func SetConfigFromSwitches(switches []SwitchSettings) ([]SwitchSettings, error) {
	return setSwitchesInternal(switches, false)
}

// RevertSwitchesConfig() reverts the CLI switch config, using the spec returned
// from SetConfigFromSwitches(). Use SetSwitches() to automate this.
func RevertSwitchesConfig(switches []SwitchSettings) error {
	_, err := setSwitchesInternal(switches, true)
	return err
}

// SetSwitches() sets the CLI switch config specified, and sets a test cleanup
// func to revert the settings at the end of the test.
func SetSwitches(t *testing.T, switches []SwitchSettings) error {
	switches, err := SetConfigFromSwitches(switches)
	if err != nil {
		return err
	}
	t.Cleanup(func() { RevertSwitchesConfig(switches) })
	return nil
}
