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

package stacktracetree

import (
	"fmt"
	"testing"
)

func TestSimple(t *testing.T) {
	fmt.Printf("Hello!\n")
	stt0 := Stt{}
	stt0.Append(0x10, "", []string{})
	stt0.Append(0x20, "", []string{})
	stt0.Append(0x30, "", []string{})

	stt1 := Stt{}
	stt1.Append(0x10, "", []string{})
	stt1.Append(0x20, "", []string{})
	stt1.Append(0x40, "", []string{})

	tree := CreateSttree()
	tree.AddStacktrace(&stt0)
	tree.Print()
	tree.AddStacktrace(&stt1)
	tree.Print()

}
