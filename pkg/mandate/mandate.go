// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

package mandate

import (
	"fmt"
	"net/url"
	"path/filepath"
	"time"

	"sigs.k8s.io/yaml"
)

type Conf struct {
	Mode string `json:"mode,omitempty"`
}

type Policy struct {
	URL   string `json:"url"`
	*Conf `json:"conf,omitempty"`

	url_  *url.URL
	mode_ string
}

func inheritURL(u *url.URL, p *url.URL) {
	// relative path: use parent as a prefix
	if u.Scheme == "" && len(u.Path) > 0 && u.Path[0] != '/' {
		u.Scheme = p.Scheme
		u.Host = p.Host
		u.Path = filepath.Join(filepath.Dir(p.Path), u.Path)
	}
}

func (p *Policy) init(m *Mandate) error {
	var err error

	p.url_, err = url.Parse(p.URL)
	if err != nil {
		return fmt.Errorf("failed to parse policy URL %q: %s", p.URL, err)
	}
	inheritURL(p.url_, m.url_)

	// if there is a mode set either in either the mandate or the poicy conf section, save it to
	// the policy
	p.mode_ = policyMode(m, p)
	return nil
}

// ownMode returns the mode configured in the policy (does not consider what is in the mandate conf)
func (p *Policy) ownMode() string {
	if p.Conf != nil && p.Mode != "" {
		return p.Mode
	}
	return ""
}

func policyMode(m *Mandate, p *Policy) string {
	if p.Conf != nil && p.Mode != "" {
		return p.Mode
	}
	return m.Conf.Mode
}

type policyData = []byte

type Mandate struct {
	Info     map[string]any `json:"info"`
	Conf     Conf           `json:"conf,omitempty"`
	Policies []Policy       `json:"policies"`

	// private convenience fields:
	url_ *url.URL // parsed URL
}

type Obj struct {
	Mandate Mandate `json:"tetragonMandate"`

	// private convenience fields:
	sha256     []byte
	loadedTime time.Time
}

func (o *Obj) SameVersion(n *Obj) bool {
	vo, voOK := o.Version()
	vn, vnOK := n.Version()
	return voOK && vnOK && vo == vn
}

func (o *Obj) Version() (string, bool) {
	val, ok := o.Mandate.Info["version"]
	if !ok {
		return "", false
	}
	ret, ok := val.(string)
	return ret, ok
}

func (o *Obj) VersionOrEmpty() string {
	v, _ := o.Version()
	return v
}

func (o *Obj) Checksum() string {
	return fmt.Sprintf("sha256:%x", o.sha256)
}

func (o *Obj) id() string {
	v, ok := o.Version()
	if ok {
		return fmt.Sprintf("%s-%x", v, o.sha256)
	}
	return fmt.Sprintf("%x", o.sha256)
}

func fetchMandateObj(urlStr string) (ret *Obj, data []byte, err error) {
	var obj Obj
	obj.Mandate.url_, err = url.Parse(urlStr)
	if err != nil {
		err = fmt.Errorf("error parsing '%s': %v", urlStr, err)
		return
	}

	data, err = fetchURL(obj.Mandate.url_)
	if err != nil {
		return
	}

	err = yaml.UnmarshalStrict(data, &obj)
	if err != nil {
		err = fmt.Errorf("error unmarshalling data: %v", err)
		return
	}

	// fill in policies private data
	for i := range obj.Mandate.Policies {
		pol := &obj.Mandate.Policies[i]
		if xerr := pol.init(&obj.Mandate); xerr != nil {
			err = fmt.Errorf("invalid policy (%+v): %s", pol, xerr)
			return
		}
	}

	ret = &obj
	return
}
