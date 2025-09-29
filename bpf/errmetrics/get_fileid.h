// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef GET_FILEID_H__
#define GET_FILEID_H__

FUNC_INLINE __u16
get_fileid__(const char *const fname)
{
#define fileid__(f, id)                  \
	if (!__builtin_strcmp(f, fname)) \
		return id;

/* OSS file IDs */
#include "../modules/tetragon-oss/bpf/errmetrics/fileids.h"
/* EE file IDs */
#include "fileids.h"

#undef fileid__

	return 0;
}

#endif /* GET_FILEID_H__ */
