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
 * Copyright IBM Corp. 2009
 */

#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <semaphore.h>
#include <unistd.h>
#include <sys/types.h>
#include "ica_api.h"
#include "include/init.h"
#include "include/s390_prng.h"
#include "include/s390_crypto.h"
#include "include/icastats.h"

#include <stdio.h>

sem_t semaphore;

/*
 * Parameter block for the KMC(PRNG) instruction.
 */
unsigned char zPRNG_PB[32] = {
	0x0F, 0x2B, 0x8E, 0x63, 0x8C, 0x8E, 0xD2, 0x52, 0x64, 0xB7, 0xA0, 0x7B,
	0x75, 0x28, 0xB8, 0xF4,
	0x75, 0x5F, 0xD2, 0xA6, 0x8D, 0x97, 0x11, 0xFF, 0x49, 0xD8, 0x23, 0xF3,
	0x7E, 0x21, 0xEC, 0xA0,
};

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
	sem_init(&semaphore, 0, 1);

	struct sigaction oldact;
	sigset_t oldset;
	int rc = -1;
	if (begin_sigill_section(&oldact, &oldset) == 0) {
		int handle;
		unsigned char seed[16];
		handle = open("/dev/hwrng", O_RDONLY);
		if (!handle)
			handle = open("/dev/urandom", O_RDONLY);
		if (handle) {
			rc = read(handle, seed, sizeof(seed));
		        if (rc != -1)
				rc = s390_prng_seed(seed, sizeof(seed) /
						    sizeof(long long));
			close(handle);
		} else
			rc = ENODEV;
	// If the original seeding failed, we should try to stir in some
	// entropy anyway (since we already put out a message).
	}
	end_sigill_section(&oldact, &oldset);
	s390_byte_count = 0;

	if (rc < 0)
		return EIO;

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
	unsigned char entropy[4 * 8];
	unsigned int K;
	int rc = 0;

	for (K = 0; K < 16; K++) {
		if ((rc = s390_stckf_hw(entropy + 0 * 8)))
			return EIO;
		if ((rc = s390_stckf_hw(entropy + 1 * 8)))
			return EIO; 
		if ((rc = s390_stckf_hw(entropy + 2 * 8)))
			return EIO;
		if ((rc = s390_stckf_hw(entropy + 3 * 8)))
			return EIO;
		if ((rc =
		     s390_kmc(0x43, zPRNG_PB, entropy, entropy, sizeof(entropy))) < 0)
			return EIO;
		memcpy(zPRNG_PB, entropy, sizeof(entropy));
	}
	int handle;
	unsigned char seed[32];
	/* Add some additional entropy. If it fails, do not care here. */
	handle = open("/dev/hwrng", O_RDONLY);
	if (handle < 1)
		handle = open("/dev/urandom", O_RDONLY);
        if (handle > 0) {
		rc = read(handle, seed, sizeof(seed));
		if (rc != -1)
			rc = s390_kmc(0x43, zPRNG_PB, seed, seed,
				      sizeof(seed));
		close(handle);
		if (rc < 0)
			return EIO;
		else
			memcpy(zPRNG_PB, seed, sizeof(seed));
	}
	if (rc > 0)
		return 0;

	return rc;
}


/*
 * This is the function that does the heavy lifting.
 *
 * It is here that the PRNG is actually done.
 */
int s390_prng(unsigned char *output_data, unsigned int output_length)
{
	int rc = 1;
	int hardware = 1;
	
	if (prng_switch)
		rc = s390_prng_hw(output_data, output_length);
	if (rc) {
		rc = s390_prng_sw(output_data, output_length);
		hardware = 0;
	}
	stats_increment(ICA_STATS_RNG, hardware);
	return rc;
}

static int s390_prng_sw(unsigned char *output_data, unsigned int output_length)
{
	ica_adapter_handle_t adapter_handle = open("/dev/urandom", O_RDONLY);
	if (adapter_handle == -1)
		return errno;
	if (read(adapter_handle, output_data, output_length) == -1) {
		close(adapter_handle);
		return errno;
	}
	close(adapter_handle);
	
	return 0;
}

static int s390_prng_hw(unsigned char *random_bytes, unsigned int num_bytes)
{
	unsigned int i, remainder;
	unsigned char last_dw[8];
	int rc = 0;

	struct sigaction oldact;
	sigset_t oldset;

	if ((rc = begin_sigill_section(&oldact, &oldset)) != 0)
		return rc;

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

		for (i = 0; !rc && i < (num_bytes / 8); i++) {
			rc = s390_stckf_hw(random_bytes + i * 8);
		}
		if (!rc) {
			rc = s390_kmc(S390_CRYPTO_PRNG, zPRNG_PB, random_bytes,
				      random_bytes, num_bytes);
			if (rc > 0) {
				s390_byte_count += rc;
				rc = 0;
			}
		}

		// If there was a remainder, we'll use an internal buffer to handle it.
		if (!rc && remainder) {
			rc = s390_stckf_hw(last_dw);
			if (!rc) {
				rc = s390_kmc(S390_CRYPTO_PRNG, zPRNG_PB, last_dw,
					      last_dw, 8);
				if (rc > 0) {
					s390_byte_count += rc;
					rc = 0;
				}
			}
			memcpy(random_bytes + num_bytes, last_dw, remainder);
		}
		if (rc < 0)
			return EIO;

	}
	end_sigill_section(&oldact, &oldset);
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
	struct sigaction oldact;
	sigset_t oldset;
	if (begin_sigill_section(&oldact, &oldset) != 0)
		return errno;

	unsigned int i;
	int rc;

	// Add entropy using the source randomization value.
	for (i = 0; i < count; i++) {
		*((uint64_t *) zPRNG_PB) ^= *((uint64_t *) srv + i * 8);
		if ((rc = s390_add_entropy()))
			break;
	}
	// Stir one last time.
	rc = s390_add_entropy();

	end_sigill_section(&oldact, &oldset);
	return rc;
}
