/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2011
 */
#include <stdint.h>

#ifndef S390_COMMON_H
#define S390_COMMON_H

/*
 * Assumption: *_ENCRYPT members of the kmc_funktion_t and kma_function_t
 * enums are even, while *_DECRYPT members are odd.
 */
#define UNDIRECTED_FC(x) (((x)/2)*2)

struct uint128 {
	uint64_t	g[2];
};

static inline void block_xor(unsigned char dest[], unsigned char a[],
    unsigned char b[], unsigned int length)
{
	unsigned int i;
	for (i = 0; i < length; i++) {
		dest[i] = a[i] ^ b[i];
	}
}

static inline void memcpy_r_allign(void *dest, int dest_bs,
    void *src, int src_bs, int size)
{
	memcpy((unsigned char *)dest + (dest_bs - size),
	       (unsigned char *)src + (src_bs - size), size);
}

#endif /* S390_COMMON_H */

