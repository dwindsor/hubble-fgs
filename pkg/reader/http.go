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

package reader

import (
	"strconv"
)

var httpMethod = map[uint32]string{
	0:  "internal-error",
	1:  "CONNECT",
	2:  "DELETE",
	3:  "GET",
	4:  "HEAD",
	5:  "OPTIONS",
	6:  "POST",
	7:  "PULL",
	8:  "PATCH",
	9:  "TRACE",
	10: "unknown",
	11: "response",
}

func GetHttpMethod(code uint32) string {
	methodName := httpMethod[code]
	if methodName == "" {
		return "unknown-method"
	}
	return methodName
}

func GetHttpCode(code string) (uint32, error) {
	i, err := strconv.ParseUint(code, 10, 32)
	if err != nil {
		return uint32(0), err
	}
	return uint32(i), err
}
