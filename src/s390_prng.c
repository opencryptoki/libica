/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Some parts of this file have been moved from former icalinux.c to this file.
 *
 * Authors: Felix Beck <felix.beck@de.ibm.com>
 *	    Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2011
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <unistd.h>
#include <sys/types.h>

#include "ica_api.h"
#include "init.h"
#include "s390_prng.h"
#include "s390_crypto.h"
#include "icastats.h"
#include "s390_drbg.h"

/*
 * On 31 bit systems we have to use the instruction STCKE while on 64 bit
 * systems we can use STCKF. STCKE uses a 16 byte buffer while STCKF uses
 * an 8 byte buffer.
 */
#ifdef _LINUX_S390X_
#define STCK_BUFFER  8
#else
#define STCK_BUFFER 16
#endif

/* State handle for the global ica_drbg instantiation. */
ica_drbg_t *ica_drbg_global = ICA_DRBG_NEW_STATE_HANDLE;

sem_t semaphore;

union zprng_pb_t {
	unsigned char ch[32];
	uint64_t uint;
};

/*
 * Parameter block for the KMC(PRNG) instruction.
 */
union zprng_pb_t zPRNG_PB = {{0x0F, 0x2B, 0x8E, 0x63, 0x8C, 0x8E, 0xD2, 0x52,
			      0x64, 0xB7, 0xA0, 0x7B, 0x75, 0x28, 0xB8, 0xF4,
			      0x75, 0x5F, 0xD2, 0xA6, 0x8D, 0x97, 0x11, 0xFF,
			      0x49, 0xD8, 0x23, 0xF3, 0x7E, 0x21, 0xEC, 0xA0}};

unsigned int s390_prng_limit = 4096;
unsigned long s390_byte_count;

/* Static functions */
static int s390_add_entropy(void);
static int s390_prng_sw(unsigned char *output_data,
			unsigned int output_length);
static int s390_prng_hw(unsigned char *random_bytes, unsigned int num_bytes);
static int s390_prng_seed(void *srv, unsigned int count);

/* Constant */
#define PRNG_BLK_SZ	8

int s390_prng_init(void)
{
	// Create a global ica_drbg instance if sha512 or sha512 drng is
	// available. However, the old prng is still initialized but
	// only used as a fallback.
	if(sha512_switch || sha512_drng_switch){
		const char *pers = "ica_drbg_global";
		ica_drbg_instantiate(&ica_drbg_global, 256, true,
				     ICA_DRBG_SHA512, (unsigned char *)pers,
				     strlen(pers));
	}

	// The old prng code starts here:
	sem_init(&semaphore, 0, 1);

	int rc = -1;
	unsigned char seed[16];

	FILE *handle = fopen("/dev/hwrng", "r");
	if (!handle)
		handle = fopen("/dev/urandom", "r");
	if (handle) {
		rc = fread(seed, sizeof(seed), 1, handle);
		fclose(handle);
	        if (1 == rc)
			rc = s390_prng_seed(seed, sizeof(seed) /
					    sizeof(long long));
		else
			rc = EIO;
	} else
		rc = ENODEV;
	// If the original seeding failed, we should try to stir in some
	// entropy anyway (since we already put out a message).
	s390_byte_count = 0;

	return rc;
}

/*
 * Adds some entropy to the system.
 *
 * This is called at the first request for random and again if more than ten
 * seconds have passed since the last request for random bytes.
 */
static int s390_add_entropy(void)
{
	unsigned char entropy[4 * STCK_BUFFER];
	unsigned int K;
	int rc = -1;

	if (!prng_switch)
		return ENOTSUP;

	for (K = 0; K < 16; K++) {
		s390_stck(entropy + 0 * STCK_BUFFER);
		s390_stck(entropy + 1 * STCK_BUFFER);
		s390_stck(entropy + 2 * STCK_BUFFER);
		s390_stck(entropy + 3 * STCK_BUFFER);
		if(s390_kmc(0x43, zPRNG_PB.ch, entropy, entropy,
			      sizeof(entropy)) < 0) {
			return EIO;
		}
		rc = 0;
		memcpy(zPRNG_PB.ch, entropy, sizeof(zPRNG_PB.ch));
	}
	unsigned char seed[32];
	/* Add some additional entropy. */
	FILE *handle = fopen("/dev/hwrng", "r");
	if (!handle)
		handle = fopen("/dev/urandom", "r");
        if (handle) {
		rc = fread(seed, sizeof(seed), 1, handle);
		fclose(handle);
		if (1 == rc){
			rc = s390_kmc(0x43, zPRNG_PB.ch, seed, seed,
				      sizeof(seed));
			if (rc >= 0)
				memcpy(zPRNG_PB.ch, seed, sizeof(seed));
			else
				return EIO;
		}
		else
			return EIO;
	}
	else
		return ENODEV;

	return 0;
}


/*
 * This is the function that does the heavy lifting.
 *
 * It is here that the PRNG is actually done.
 */
int s390_prng(unsigned char *output_data, unsigned int output_length)
{
	// Try to use the global ica_drbg instantiation. If it does not exist
	// or it does not work, the old prng code is used.
	if(ica_drbg_global){
		int status = 0;

		const size_t
		q = output_length / ICA_DRBG_SHA512->max_no_of_bytes_per_req;
		const size_t
		r = output_length % ICA_DRBG_SHA512->max_no_of_bytes_per_req;

		unsigned char *ptr = output_data;
		size_t i = 0;
		for(; i < q; i++){
			status = ica_drbg_generate(ica_drbg_global, 256, true,
						   NULL, 0, ptr,
						   ICA_DRBG_SHA512
						   ->max_no_of_bytes_per_req);
			if(status)
				break;

			ptr += ICA_DRBG_SHA512->max_no_of_bytes_per_req;
		}
		if(!status){
			status = ica_drbg_generate(ica_drbg_global, 256, true,
						   NULL, 0, ptr, r);
			if(!status)
				return 0;
		}
	}

	// Old prng code starts here:
	int rc = 1;
	int hardware = ALGO_HW;

	if (prng_switch)
		rc = s390_prng_hw(output_data, output_length);
	if (rc) {
		rc = s390_prng_sw(output_data, output_length);
		hardware = ALGO_SW;
	}
	stats_increment(ICA_STATS_PRNG, hardware, ENCRYPT);
	return rc;
}

static int s390_prng_sw(unsigned char *output_data, unsigned int output_length)
{
	FILE *handle = fopen("/dev/urandom", "r");
	if (!handle)
		return ENODEV;
	if (1 != fread(output_data, output_length, 1, handle)) {
		fclose(handle);
		return EIO;
	}

	fclose(handle);
	return 0;
}

static int s390_prng_hw(unsigned char *random_bytes, unsigned int num_bytes)
{
	unsigned int i, remainder;
	unsigned char last_dw[STCK_BUFFER];
	int rc = -1;

	rc = 0;

	sem_wait(&semaphore);

	/* Add some additional entropy when the byte count is reached.*/
	if (s390_byte_count > s390_prng_limit)
		rc = s390_add_entropy();

	if (!rc) {
		/* The kmc(PRNG) instruction requires a multiple of PRNG_BLK_SZ, so we
		 * will save the remainder and then do a final chunk if we have
		 * non-zero remainder.
		 */
		remainder = num_bytes % PRNG_BLK_SZ;
		num_bytes -= remainder;

		for (i = 0; i < (num_bytes / STCK_BUFFER); i++)
			s390_stck(random_bytes + i * STCK_BUFFER);

		rc = s390_kmc(S390_CRYPTO_PRNG, zPRNG_PB.ch, random_bytes,
			      random_bytes, num_bytes);
		if (rc > 0) {
			s390_byte_count += rc;
			rc = 0;
		}

		// If there was a remainder, we'll use an internal buffer to handle it.
		if (!rc && remainder) {
			s390_stck(last_dw);
			rc = s390_kmc(S390_CRYPTO_PRNG, zPRNG_PB.ch, last_dw,
				      last_dw, STCK_BUFFER);
			if (rc > 0) {
				s390_byte_count += rc;
				rc = 0;
			}
			memcpy(random_bytes + num_bytes, last_dw, remainder);
		}
		if (rc < 0)
			return EIO;
		else
			rc = 0;

	}
	sem_post(&semaphore);

	return rc;
}

/*
 * This is the function that seeds the random number generator.
 * SRV is the source randomization value.
 * count is the number of doublewords (8 bytes) in the SRV..
 */
static int s390_prng_seed(void *srv, unsigned int count)
{
	int rc = -1;
	unsigned int i;

	if (!prng_switch)
		return ENOTSUP;

	// Add entropy using the source randomization value.
	for (i = 0; i < count; i++) {
		zPRNG_PB.uint ^= *((uint64_t *) srv + i * 8);
		if ((rc = s390_add_entropy()))
			break;
	}
	// Stir one last time.
	rc = s390_add_entropy();
	return rc;
}
