//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.
//

package observer

import (
	"context"
	"fmt"

	"github.com/isovalent/hubble-fgs/pkg/logger"
)

type standaloneListener struct {
}

func (sl *standaloneListener) Notify(msg interface{}) error {
	_, err := fmt.Printf("=> %v\n", msg)
	return err
}

func (sl *standaloneListener) Close() error {
	return nil
}

func (k *Observer) StartStandalone(ctx context.Context) error {
	if len(k.listeners) > 0 {
		return fmt.Errorf("hubble-fgs, Cowardly refusing to start in standalone mode with other listeners registered")
	}
	logger.GetLogger().Info("starting observer in standalone mode")
	k.AddListener(&standaloneListener{})
	return k.Start(ctx)
}
