/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Ruben Straus <rstraus@de.ibm.com>
 * 	    Holger Dengler <hd@linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2010, 2011
 */

#ifndef S390_CMAC
#define S390_CMAC_H

int s390_cmac(unsigned long fc,
	      const unsigned char *message, unsigned long message_length,
	      unsigned int key_length, const unsigned char *key,
	      unsigned int cmac_length, unsigned char *cmac,
	      unsigned char *iv);

#endif

