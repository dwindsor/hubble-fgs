//  Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
//  NOTICE: All information contained herein is, and remains the property of
//  Isovalent Inc and its suppliers, if any. The intellectual and technical
//  concepts contained herein are proprietary to Isovalent Inc and its suppliers
//  and may be covered by U.S. and Foreign Patents, patents in process, and are
//  protected by trade secret or copyright law.  Dissemination of this information
//  or reproduction of this material is strictly forbidden unless prior written
//  permission is obtained from Isovalent Inc.

package file

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"hash"

	"github.com/cilium/tetragon/api/v1/tetragon"
)

const (
	IMA_MAX_DIGEST_SIZE = 64
)

var (
	HashAlgoLen = map[tetragon.DigestAlgo]int{
		tetragon.DigestAlgo_HASH_ALGO_MD4:          16,
		tetragon.DigestAlgo_HASH_ALGO_MD5:          16,
		tetragon.DigestAlgo_HASH_ALGO_SHA1:         20,
		tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_160:  20,
		tetragon.DigestAlgo_HASH_ALGO_SHA256:       32,
		tetragon.DigestAlgo_HASH_ALGO_SHA384:       48,
		tetragon.DigestAlgo_HASH_ALGO_SHA512:       64,
		tetragon.DigestAlgo_HASH_ALGO_SHA224:       28,
		tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_128:  16,
		tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_256:  32,
		tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_320:  40,
		tetragon.DigestAlgo_HASH_ALGO_WP_256:       32,
		tetragon.DigestAlgo_HASH_ALGO_WP_384:       48,
		tetragon.DigestAlgo_HASH_ALGO_WP_512:       64,
		tetragon.DigestAlgo_HASH_ALGO_TGR_128:      16,
		tetragon.DigestAlgo_HASH_ALGO_TGR_160:      20,
		tetragon.DigestAlgo_HASH_ALGO_TGR_192:      24,
		tetragon.DigestAlgo_HASH_ALGO_SM3_256:      32,
		tetragon.DigestAlgo_HASH_ALGO_STREEBOG_256: 32,
		tetragon.DigestAlgo_HASH_ALGO_STREEBOG_512: 64,
	}

	HashNameAlgo = map[string]tetragon.DigestAlgo{
		"md4":         tetragon.DigestAlgo_HASH_ALGO_MD4,
		"md5":         tetragon.DigestAlgo_HASH_ALGO_MD5,
		"sha1":        tetragon.DigestAlgo_HASH_ALGO_SHA1,
		"rmd160":      tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_160,
		"sha256":      tetragon.DigestAlgo_HASH_ALGO_SHA256,
		"sha384":      tetragon.DigestAlgo_HASH_ALGO_SHA384,
		"sha512":      tetragon.DigestAlgo_HASH_ALGO_SHA512,
		"sha224":      tetragon.DigestAlgo_HASH_ALGO_SHA224,
		"rmd128":      tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_128,
		"rmd256":      tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_256,
		"rmd320":      tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_320,
		"wp256":       tetragon.DigestAlgo_HASH_ALGO_WP_256,
		"wp384":       tetragon.DigestAlgo_HASH_ALGO_WP_384,
		"wp512":       tetragon.DigestAlgo_HASH_ALGO_WP_512,
		"tgr128":      tetragon.DigestAlgo_HASH_ALGO_TGR_128,
		"tgr160":      tetragon.DigestAlgo_HASH_ALGO_TGR_160,
		"tgr192":      tetragon.DigestAlgo_HASH_ALGO_TGR_192,
		"sm3":         tetragon.DigestAlgo_HASH_ALGO_SM3_256,
		"streebog256": tetragon.DigestAlgo_HASH_ALGO_STREEBOG_256,
		"streebog512": tetragon.DigestAlgo_HASH_ALGO_STREEBOG_512,
	}

	HashAlgoName = map[tetragon.DigestAlgo]string{
		tetragon.DigestAlgo_HASH_ALGO_MD4:          "md4",
		tetragon.DigestAlgo_HASH_ALGO_MD5:          "md5",
		tetragon.DigestAlgo_HASH_ALGO_SHA1:         "sha1",
		tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_160:  "rmd160",
		tetragon.DigestAlgo_HASH_ALGO_SHA256:       "sha256",
		tetragon.DigestAlgo_HASH_ALGO_SHA384:       "sha384",
		tetragon.DigestAlgo_HASH_ALGO_SHA512:       "sha512",
		tetragon.DigestAlgo_HASH_ALGO_SHA224:       "sha224",
		tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_128:  "rmd128",
		tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_256:  "rmd256",
		tetragon.DigestAlgo_HASH_ALGO_RIPE_MD_320:  "rmd320",
		tetragon.DigestAlgo_HASH_ALGO_WP_256:       "wp256",
		tetragon.DigestAlgo_HASH_ALGO_WP_384:       "wp384",
		tetragon.DigestAlgo_HASH_ALGO_WP_512:       "wp512",
		tetragon.DigestAlgo_HASH_ALGO_TGR_128:      "tgr128",
		tetragon.DigestAlgo_HASH_ALGO_TGR_160:      "tgr160",
		tetragon.DigestAlgo_HASH_ALGO_TGR_192:      "tgr192",
		tetragon.DigestAlgo_HASH_ALGO_SM3_256:      "sm3",
		tetragon.DigestAlgo_HASH_ALGO_STREEBOG_256: "streebog256",
		tetragon.DigestAlgo_HASH_ALGO_STREEBOG_512: "streebog512",
	}
)

func GetHashAlgo(algo int32) (hash.Hash, error) {
	var h hash.Hash
	switch tetragon.DigestAlgo(algo) {
	case tetragon.DigestAlgo_HASH_ALGO_SHA1:
		h = sha1.New()
	case tetragon.DigestAlgo_HASH_ALGO_SHA224:
		h = sha256.New224()
	case tetragon.DigestAlgo_HASH_ALGO_SHA256:
		h = sha256.New()
	case tetragon.DigestAlgo_HASH_ALGO_SHA384:
		h = sha512.New384()
	case tetragon.DigestAlgo_HASH_ALGO_SHA512:
		h = sha512.New()
	case tetragon.DigestAlgo_HASH_ALGO_MD5:
		h = md5.New()
	default:
		return h, fmt.Errorf("tracingPolicyFileDigests: Unsupported digest algo: %d", algo)
	}

	return h, nil
}
