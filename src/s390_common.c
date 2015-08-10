/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2011, 2012
 */

#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "ica_api.h"
#include "icastats.h"
#include "init.h"
#include "s390_crypto.h"
#include "s390_aes.h"
#include "s390_des.h"
#include "s390_common.h"

void ctr_inc_block(unsigned char *iv, unsigned int block_size,
		   unsigned int ctr_width, unsigned char *ctrlist,
		   unsigned long ctrlist_length)
{
	ctr128_t tmp_ctr = { 0ul, 0ul };
	unsigned char *dest;
	unsigned int ctr_byte_width;

	ctr_byte_width = ctr_width / 8;

	// init counter with iv
	memcpy_r_allign((void *)&tmp_ctr, sizeof(tmp_ctr),
			iv, block_size, block_size);

	for (dest = ctrlist;
	     dest < (ctrlist + ctrlist_length);
	     dest += block_size) {
		// copy nounce to ctrlist
		memcpy(dest, iv, block_size - ctr_byte_width);

		// add counter values to ctrlist
		memcpy_r_allign(dest, block_size, (void *)&tmp_ctr,
				sizeof(tmp_ctr), ctr_byte_width);
		__inc(&tmp_ctr);
	}

	// update iv for chaining
	memcpy_r_allign(iv, block_size, (void *)&tmp_ctr,
			  sizeof(tmp_ctr), ctr_byte_width);
}

void ctr_inc_single(unsigned char *iv, unsigned int block_size,
			   unsigned int ctr_width)
{
	ctr128_t tmp_ctr = { 0ul, 0ul };
	unsigned int ctr_byte_width;

	ctr_byte_width = ctr_width / 8;

	// init counter with iv
	memcpy_r_allign((void *)&tmp_ctr, sizeof(tmp_ctr), iv, block_size, block_size);

	__inc(&tmp_ctr);

	// update iv for chaining
	memcpy_r_allign(iv, block_size, (void *)&tmp_ctr, sizeof(tmp_ctr), ctr_byte_width);
}


