/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 * 	    Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2010, 2011
 */

#include "s390_common.h"

#ifndef S390_CTR_H
#define S390_CTR_H

/* get next multiple of blocksize (bs) of n */
#define NEXT_BS(n, bs) ((n + (bs - 1)) & (~(bs - 1)))

#define LARGE_MSG_CHUNK 4096	/* page size */

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
