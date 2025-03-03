//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package mandate

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/isovalent/hubble-fgs/pkg/attempt"
)

func fetchURL(u *url.URL) ([]byte, error) {
	s := u.String()
	switch u.Scheme {
	case "", "file":
		data, err := os.ReadFile(u.Path)
		if err != nil {
			return nil, fmt.Errorf("error reading file %q: %v", s, err)
		}
		return data, nil

	case "https", "http":
		res, err := http.Get(s)
		if err != nil {
			return nil, fmt.Errorf("error getting URL %q: %v", s, err)
		}
		defer res.Body.Close()
		data, err := io.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("error getting URL %q: %v", s, err)
		}
		return data, nil

	default:
		return nil, fmt.Errorf("unsupported url %q: unknown scheme", s)
	}
}

func attemptFetchURL(att *attempt.InprAttempt, u *url.URL) ([]byte, error) {
	att = att.WithInfo("url", u.String())
	ret, err := fetchURL(u)
	att.Complete(err)
	return ret, err
}
