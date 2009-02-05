/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009
 */

#ifndef S390_PRNG_H
#define S390_PRNG_H

int s390_prng_init(void);
int s390_prng(unsigned char *output_data, unsigned int output_length);
#endif

