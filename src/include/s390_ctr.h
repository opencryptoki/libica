/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 * 	    Holger Dengler <hd@linux.vnet.ibm.com>
 * 	    Patrick Steuer <patrick.steuer@de.ibm.com>
 *
 * Copyright IBM Corp. 2010, 2011
 */

#ifndef S390_CTR_H
#define S390_CTR_H

#include "s390_common.h"

/*
 * Get least multiple of @bs that is greater or equal than @n.
 */
#define NEXT_BS(n, bs) ((n + (bs - 1)) & (~(bs - 1)))

#define LARGE_MSG_CHUNK 4096	/* page size */

static inline void __inc_des_ctr(uint64_t *iv, int ctr_bits)
{
	uint64_t ctr, mask;

	ctr = *iv;
	if (ctr_bits >= 64)
		mask = 0ULL;
	else
		mask = ~0ULL << ctr_bits;
	*iv &= mask;
	++ctr;
	*iv |= ctr & ~mask;
}

static inline void __inc_aes_ctr(struct uint128 *iv, int ctr_bits)
{
	struct uint128 ctr, mask;

	ctr.g[1] = iv->g[1];
	ctr.g[0] = iv->g[0];
	if (ctr_bits >= 64) {
		mask.g[1] = 0ULL;
		mask.g[0] = ~0ULL << (ctr_bits - 64);
	}
	else {
		mask.g[1] = ~0ULL << ctr_bits;
		mask.g[0] = ~0ULL;
	}
	iv->g[1] &= mask.g[1];
	iv->g[0] &= mask.g[0];
	if(++(ctr.g[1]))
		++(ctr.g[0]);
	iv->g[1] |= ctr.g[1] & ~mask.g[1];
	iv->g[0] |= ctr.g[0] & ~mask.g[0];
}

/*
 * Fill @ctrlist with 8 byte counter blocks. @ctrlistlen must be a multiple of
 * 8 (DES_BLOCK_SIZE).
 */
static inline void __fill_des_ctrlist(uint8_t *ctrlist, size_t ctrlistlen,
    uint64_t *iv, int ctr_bits) {
	uint64_t ctr, mask, *block;

	ctr = *iv;
	if (ctr_bits >= 64)
		mask = 0ULL;
	else
		mask = ~0ULL << ctr_bits;

	*iv &= mask;
	for (block = (uint64_t *)ctrlist; block < (uint64_t *)ctrlist +
	    ctrlistlen / sizeof(uint64_t); block++) {
		*block = (ctr & ~mask) | *iv;
		++ctr;
	}
	*iv |= ctr & ~mask;
}

/*
 * Fill @ctrlist with 16 byte counter blocks. @ctrlistlen must be a multiple of
 * 16 (AES_BLOCK_SIZE).
 */
static inline void __fill_aes_ctrlist(uint8_t *ctrlist, size_t ctrlistlen,
    struct uint128 *iv, int ctr_bits) {
	struct uint128 ctr, mask, *block;

	ctr.g[1] = iv->g[1];
	ctr.g[0] = iv->g[0];
	if (ctr_bits >= 64) {
		mask.g[1] = 0ULL;
		mask.g[0] = ~0ULL << (ctr_bits - 64);
	}
	else {
		mask.g[1] = ~0ULL << ctr_bits;
		mask.g[0] = ~0ULL;
	}
	iv->g[1] &= mask.g[1];
	iv->g[0] &= mask.g[0];
	for (block = (struct uint128 *)ctrlist; block <
	    (struct uint128 *)ctrlist + ctrlistlen / sizeof(struct uint128);
	    block++) {
		block->g[1] = (ctr.g[1] & ~mask.g[1]) | iv->g[1];
		block->g[0] = (ctr.g[0] & ~mask.g[0]) | iv->g[0];
		if(++(ctr.g[1]))
			++(ctr.g[0]);
	}
	iv->g[1] |= ctr.g[1] & ~mask.g[1];
	iv->g[0] |= ctr.g[0] & ~mask.g[0];
}

static inline int s390_ctr_hw(unsigned int function_code, unsigned long data_length,
		       const unsigned char *in_data, unsigned char *key,
		       unsigned char *out_data, const unsigned char *ctrlist)
{
	int rc = -1;
	rc = s390_kmctr(function_code, key, out_data, in_data,
			data_length, (unsigned char *)ctrlist);
	if (rc >= 0)
		return 0;
	else
		return EIO;
}

#endif
