// Copyright (C) Isovalent, Inc. - All Rights Reserved.
//
// NOTICE: All information contained herein is, and remains the property of
// Isovalent Inc and its suppliers, if any. The intellectual and technical
// concepts contained herein are proprietary to Isovalent Inc and its suppliers
// and may be covered by U.S. and Foreign Patents, patents in process, and are
// protected by trade secret or copyright law.  Dissemination of this information
// or reproduction of this material is strictly forbidden unless prior written
// permission is obtained from Isovalent Inc.

#ifndef _TG_JHASH_H
#define _TG_JHASH_H

// jhash is an implementation of jhash
// (https://elixir.bootlin.com/linux/v7.0/source/include/linux/jhash.h)
// that has been modified to remove the get_unaligned() macro calls.
// This function must always be called with a fixed length. Even then,
// at lengths >12, it may need modifying to appease the verifier.

#include <vmlinux.h>
#include "lib/bpf_helpers.h"

/**
 * rol32 - rotate a 32-bit value left
 * @word: value to rotate
 * @shift: bits to roll
 * Copied from https://elixir.bootlin.com/linux/v7.0/source/include/linux/bitops.h
 */
static inline __attribute__((always_inline)) __u32 rol32(__u32 word, unsigned int shift)
{
	return (word << (shift & 31)) | (word >> ((-shift) & 31));
}

/* __jhash_mix - mix 3 32-bit values reversibly.
 * Converted from a macro to an inline function as it upset the style checkers.
 */
static inline __attribute__((always_inline)) void
__jhash_mix(u32 *a, u32 *b, u32 *c)
{
	*a -= *c;
	*a ^= rol32(*c, 4);
	*c += *b;
	*b -= *a;
	*b ^= rol32(*a, 6);
	*a += *c;
	*c -= *b;
	*c ^= rol32(*b, 8);
	*b += *a;
	*a -= *c;
	*a ^= rol32(*c, 16);
	*c += *b;
	*b -= *a;
	*b ^= rol32(*a, 19);
	*a += *c;
	*c -= *b;
	*c ^= rol32(*b, 4);
	*b += *a;
}

/* __jhash_final - final mixing of 3 32-bit values (a,b,c) into c
 * Converted from a macro to an inline function as it upset the style checkers.
 */
static inline __attribute__((always_inline)) void
__jhash_final(u32 *a, u32 *b, u32 *c)
{
	*c ^= *b;
	*c -= rol32(*b, 14);
	*a ^= *c;
	*a -= rol32(*c, 11);
	*b ^= *a;
	*b -= rol32(*a, 25);
	*c ^= *b;
	*c -= rol32(*b, 16);
	*a ^= *c;
	*a -= rol32(*c, 4);
	*b ^= *a;
	*b -= rol32(*a, 14);
	*c ^= *b;
	*c -= rol32(*b, 24);
}

/* An arbitrary initial parameter */
#define JHASH_INITVAL 0xdeadbeef

/* jhash - hash an arbitrary key
 * @k: sequence of bytes as key
 * @length: the length of the key
 * @initval: the previous hash, or an arbitrary value
 *
 * The generic version, hashes an arbitrary sequence of bytes.
 * No alignment or length assumptions are made about the input key.
 *
 * Returns the hash value of the key. The result depends on endianness.
 *
 * Copied and modified from https://elixir.bootlin.com/linux/v7.0/source/include/linux/jhash.h
 */
static inline __attribute__((always_inline)) u32 jhash(const void *key, u32 length, u32 initval)
{
	u32 a, b, c;
	const u8 *k = (const u8 *)key;

	/* Set up the internal state */
	a = JHASH_INITVAL + length + initval;
	b = a;
	c = a;

	/* All but the last block: affect some 32 bits of (a,b,c) */
	while (length > 12) {
		a += *((u32 *)k);
		b += *((u32 *)(k + 4));
		c += *((u32 *)(k + 8));
		__jhash_mix(&a, &b, &c);
		length -= 12;
		k += 12;
	}
	/* Last block: affect all 32 bits of (c) */
	switch (length) {
	case 12:
		c += (u32)k[11] << 24;
		fallthrough;
	case 11:
		c += (u32)k[10] << 16;
		fallthrough;
	case 10:
		c += (u32)k[9] << 8;
		fallthrough;
	case 9:
		c += k[8];
		fallthrough;
	case 8:
		b += (u32)k[7] << 24;
		fallthrough;
	case 7:
		b += (u32)k[6] << 16;
		fallthrough;
	case 6:
		b += (u32)k[5] << 8;
		fallthrough;
	case 5:
		b += k[4];
		fallthrough;
	case 4:
		a += (u32)k[3] << 24;
		fallthrough;
	case 3:
		a += (u32)k[2] << 16;
		fallthrough;
	case 2:
		a += (u32)k[1] << 8;
		fallthrough;
	case 1:
		a += k[0];
		__jhash_final(&a, &b, &c);
		break;
	case 0: /* Nothing left to add */
		break;
	}

	return c;
}

#endif // _TG_JHASH_H
