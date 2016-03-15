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

/*
 * The following functions are waiting to be removed...
 */
__attribute__ ((__deprecated__))
void ctr_inc_block(unsigned char *iv, unsigned int block_size,
    unsigned int ctr_width, unsigned char *ctrlist,
    unsigned long ctrlist_length)
{
}
__attribute__ ((__deprecated__))
void ctr_inc_single(unsigned char *iv, unsigned int block_size,
    unsigned int ctr_width)
{
}
