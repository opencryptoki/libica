/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Christian Maaser <cmaaser@de.ibm.com>
 * 	    Benedikt Klotz   <benedikt.klotz@de.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2013
 */

#ifndef __ICA_STATS_H__
#define __ICA_STATS_H__

#include <stdint.h>


typedef struct crypt_opts{
	uint32_t hw;
	uint32_t sw;
} crypt_opts_t;

typedef struct statis_entry {
	crypt_opts_t  enc;
	crypt_opts_t  dec;
} stats_entry_t;


typedef enum stats_fields {
	/* crypt counter */
	ICA_STATS_SHA1 = 0,
	ICA_STATS_SHA224,
	ICA_STATS_SHA256,
	ICA_STATS_SHA384,
	ICA_STATS_SHA512,
	ICA_STATS_SHA512_224,
	ICA_STATS_SHA512_256,
	ICA_STATS_SHA3_224,
	ICA_STATS_SHA3_256,
	ICA_STATS_SHA3_384,
	ICA_STATS_SHA3_512,
	ICA_STATS_SHAKE_128,
	ICA_STATS_SHAKE_256,
	ICA_STATS_GHASH,
	ICA_STATS_PRNG,
	ICA_STATS_DRBGSHA512,
	ICA_STATS_ECDH,
	ICA_STATS_ECDSA_SIGN,
	ICA_STATS_ECDSA_VERIFY,
	ICA_STATS_ECKGEN,
	ICA_STATS_RSA_ME,
	ICA_STATS_RSA_CRT, /* add new crypt counters above RSA_CRT
			      (see print_stats function) */

	/* enc and dec counter  */
	ICA_STATS_DES_ECB,
	ICA_STATS_DES_CBC,
	ICA_STATS_DES_OFB,
	ICA_STATS_DES_CFB,
	ICA_STATS_DES_CTR,
	ICA_STATS_DES_CMAC,
	ICA_STATS_3DES_ECB,
	ICA_STATS_3DES_CBC,
	ICA_STATS_3DES_OFB,
	ICA_STATS_3DES_CFB,
	ICA_STATS_3DES_CTR,
	ICA_STATS_3DES_CMAC,
	ICA_STATS_AES_ECB,
	ICA_STATS_AES_CBC,
	ICA_STATS_AES_OFB,
	ICA_STATS_AES_CFB,
	ICA_STATS_AES_CTR,
	ICA_STATS_AES_CMAC,
	ICA_STATS_AES_XTS,
	ICA_STATS_AES_GCM,

	/* number of counters */
	ICA_NUM_STATS
} stats_fields_t;

#define STAT_STRINGS	\
	"SHA-1",      	\
	"SHA-224",    	\
	"SHA-256",    	\
	"SHA-384",    	\
	"SHA-512",    	\
	"SHA-512/224",	\
	"SHA-512/256",	\
	"SHA3-224",    	\
	"SHA3-256",    	\
	"SHA3-384",    	\
	"SHA3-512",    	\
	"SHAKE-128",   	\
	"SHAKE-256",   	\
	"GHASH",      	\
	"P_RNG",      	\
	"DRBG-SHA-512",	\
	"ECDH",         \
	"ECDSA Sign",   \
	"ECDSA Verify", \
	"ECKGEN",       \
	"RSA-ME",     	\
	"RSA-CRT",    	\
	"DES ECB",    	\
	"DES CBC",    	\
	"DES OFB",    	\
	"DES CFB",    	\
	"DES CTR",    	\
	"DES CMAC",   	\
	"3DES ECB",   	\
	"3DES CBC",   	\
	"3DES OFB",   	\
	"3DES CFB",   	\
	"3DES CTR",   	\
	"3DES CMAC",	\
	"AES ECB",	\
	"AES CBC",	\
	"AES OFB",	\
	"AES CFB",	\
	"AES CTR",	\
	"AES CMAC",	\
	"AES XTS",  \
	"AES GCM"



#define STATS_SHM_SIZE (sizeof(stats_entry_t) * ICA_NUM_STATS)
#define ENCRYPT 1
#define DECRYPT 0

#define ALGO_SW 0
#define ALGO_HW 1

#define SHM_CLOSE 0
#define SHM_DESTROY 1


int stats_mmap(int user);
void stats_munmap(int unlink);
uint32_t stats_query(stats_fields_t field, int hardware, int direction);
void get_stats_data(stats_entry_t *entries);
void stats_increment(stats_fields_t field, int hardware, int direction);
int get_stats_sum(stats_entry_t *sum);
char *get_next_usr();
void stats_reset();
int delete_all();


#endif
