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
#include <sys/types.h>

#ifndef S390_COMMON_H
#define S390_COMMON_H

#define UNDIRECTED_FC(x) (((x)/2)*2)

void ctr_inc_block(unsigned char *iv, unsigned int block_size,
		   unsigned int ctr_width, unsigned char *ctrlist,
		   unsigned long ctrlist_length);

void ctr_inc_single(unsigned char *iv, unsigned int block_size,
		    unsigned int ctr_width);

static inline void memcpy_r_allign(void *dest, int dest_bs,
			    void *src, int src_bs, int size)
{
	memcpy(dest + (dest_bs - size), src + (src_bs - size), size);
}

static inline void block_xor(unsigned char dest[],
		      unsigned char a[], unsigned char b[],
		      unsigned int length)
{
	unsigned int i;
	for (i = 0; i < length; i++) {
		dest[i] = a[i] ^ b[i];
	}
}

typedef struct {
	u_int64_t upper_half;
	u_int64_t lower_half;
} ctr128_t;

static inline void __inc(ctr128_t *ctr)
{
	if (!(++(ctr->lower_half)))
		(ctr->upper_half)++;
}
#endif /* S390_COMMON_H */

