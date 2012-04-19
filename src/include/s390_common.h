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

#ifndef S390_COMMON_H
#define S390_COMMON_H

#define UNDIRECTED_FC(x) (((x)/2)*2)

void ctr_inc_block(unsigned char *iv, unsigned int block_size,
		   unsigned int ctr_width, unsigned char *ctrlist,
		   unsigned long ctrlist_length);

void ctr_inc_single(unsigned char *iv, unsigned int block_size,
		    unsigned int ctr_width);

inline void memcpy_r_allign(void *dest, int dest_bs,
		     void *src, int src_bs, int size);

inline void block_xor(unsigned char dest[],
		      unsigned char a[], unsigned char b[],
		      unsigned int length);

#endif /* S390_COMMON_H */

