// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef _STRNCMP__
#define _STRNCMP__

/* Do not call this directly. Instead, use the strncmp_truncated macro.
 */
static inline __attribute__((always_inline)) int
__strncmp_truncated(const char *s1, __u32 s1_sz, const char *s2, __u32 s2_sz)
{
	int diff;
	int i;

	for (i = 0; i < s1_sz && i < s2_sz; i++) {
		diff = s1[i] - s2[i];
		if (diff != 0) {
			return diff;
		}
	}
	return 0;
}

/* Do a string compare between two strings. The second string s2 should be
 * fixed-size. This function will truncate the string compare to avoid verifier
 * complexity issues.
 */
#define strncmp_truncated(s1, sz, s2) \
	__strncmp_truncated(s1, sz, s2, sizeof(s2) - 1)

/* Do not call this directly. Instead, use the strncmp_exact macro.
 */
static inline __attribute__((always_inline)) int
__strncmp_exact(const char *s1, __u32 s1_sz, const char *s2, __u32 s2_sz)
{
	/* Unlike __strncmp_truncated, require the lengths to match so that a
	 * token which merely shares a prefix with s2 (e.g. "getx" vs "get",
	 * "hostname" vs "host") is not treated as equal.
	 */
	if (s1_sz != s2_sz)
		return (int)s1_sz - (int)s2_sz;

	return __strncmp_truncated(s1, s1_sz, s2, s2_sz);
}

/* Do an exact string compare between two strings. The second string s2 should
 * be fixed-size. The compare succeeds only when s1 has the same length as s2
 * and all bytes match.
 */
#define strncmp_exact(s1, sz, s2) \
	__strncmp_exact(s1, sz, s2, sizeof(s2) - 1)

#endif // _STRNCMP__
