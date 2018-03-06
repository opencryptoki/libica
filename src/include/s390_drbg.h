/*
 * This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 *
 * DRBG conforming to NIST SP800-90A
 *
 * Author(s): Patrick Steuer <patrick.steuer@de.ibm.com>
 *
 * Copyright IBM Corp. 2015
 *
 * This file contains infrastructure that should be used when implementing more
 * DRBG mechanisms. Don't forget to add the new DRBG mechanism to the DRBG
 * mechanism list.
 */

#ifndef S390_DRBG_H
#define S390_DRBG_H

#include <pthread.h>

#define DRBG_ADD_ENTROPY_LEN	18	/* bytes of entropy input used in
					   addition to the required minimum */
#define DRBG_NONCE_LEN	16		/* byte length of nonce */
#define DRBG_OUT_LEN	(512 / 8)	/* byte length of SHA-512 output */

/*
 * DRBG security strengths (bits)
 */
#define DRBG_SEC_112	112
#define DRBG_SEC_128	128
#define DRBG_SEC_192	192
#define DRBG_SEC_256	256

/*
 * DRBG mechanism function return codes
 */
/* error flags (> 0):			*/
#define DRBG_RESEED_REQUIRED		1
#define DRBG_NOMEM			2
#define DRBG_SH_INV			3
#define DRBG_MECH_INV			4
#define DRBG_PERS_INV			5
#define DRBG_ADD_INV			6
#define DRBG_REQUEST_INV		7
#define DRBG_NONCE_INV			8
#define DRBG_SEC_NOTSUPP		9
#define DRBG_PR_NOTSUPP			10
/* catastrophic error flags (< 0):	*/
#define DRBG_HEALTH_TEST_FAIL		(-1)
#define DRBG_ENTROPY_SOURCE_FAIL	(-2)

/*
 * DRBG mechanism type
 */
struct ica_drbg_mech{
	const char *id;

	/* Mechanism constants */
	const int highest_supp_sec;
	const size_t seed_len;
	const size_t max_pers_len;
	const size_t max_add_len;
	const size_t max_len;
	const size_t max_no_of_bytes_per_req;
	const uint64_t reseed_intervall;

	/* Pointers to mechanism functions */
	int (*instantiate)(void **ws,
			   int sec,
			   const unsigned char *pers,
			   size_t pers_len,
			   const unsigned char *entropy,
			   size_t entropy_len,
			   const unsigned char *nonce,
			   size_t nonce_len);

	int (*reseed)(void *ws,
		      const unsigned char *add,
		      size_t add_len,
		      const unsigned char *entropy,
		      size_t entropy_len);

	int (*generate)(void *ws,
			const unsigned char *add,
			size_t add_len,
			unsigned char *prnd_bytes,
			size_t prnd_bytes_len);

	int (*uninstantiate)(void **ws,
			     bool test_mode);

	int (*health_test)(void *func,
			   int sec,
			   bool pr);

	/* Health testing: A thread holds this wrlock while performing
	 * self-tests such that no other thread can do a generate operation in
	 * this time: generate requires this rdlock (11.3). */
	pthread_rwlock_t lock;
	const uint64_t test_intervall;
	uint64_t test_ctr;
	int error_state;
};

/*
 * DRBG type
 */
struct ica_drbg{
	pthread_mutex_t lock;	/* serialize operations on working state */
	ica_drbg_mech_t *mech;	/* DRBG mechanism */

	/*
	 * Internal state
	 */
	void *ws;		/* working state */
				/* administrative information: */
	int sec;		/* security strength */
	bool pr;		/* prediction resistance flag */
};

/*
 * DRBG mechanism list. Add new DRBG mechanism here:
 */
extern ica_drbg_mech_t DRBG_SHA512;

extern ica_drbg_mech_t *const DRBG_MECH_LIST[];
extern const size_t DRBG_MECH_LIST_LEN;

/*
 * DRBG SEI (source of entropy input) list. Add devices/change priorities here:
 */
extern const char *const DRBG_SEI_LIST[];
extern const size_t DRBG_SEI_LIST_LEN;

/*
 * DRBG mechanism functions
 *
 * @test_mode = true enables testing interface (see 11.2).
 */
int drbg_instantiate(ica_drbg_t **sh,
		     int sec,
		     bool pr,
		     ica_drbg_mech_t *mech,
		     const unsigned char *pers,
		     size_t pers_len,
		     bool test_mode,
		     const unsigned char *test_nonce,
		     size_t test_nonce_len,
		     const unsigned char *test_entropy,
		     size_t test_entropy_len);

int drbg_reseed(ica_drbg_t *sh,
		bool pr,
		const unsigned char *add,
		size_t add_len,
		bool test_mode,
		const unsigned char *entropy,
		size_t entropy_len);

int drbg_generate(ica_drbg_t *sh,
		  int sec,
		  bool pr,
		  const unsigned char *add,
		  size_t add_len,
		  bool test_mode,
		  const unsigned char *test_entropy,
		  size_t test_entropy_len,
		  unsigned char *prnd,
		  size_t prnd_len);

int drbg_uninstantiate(ica_drbg_t **sh,
		       bool test_mode);

int drbg_health_test(const void *func,
		     int sec,
		     bool pr,
		     ica_drbg_mech_t *mech);

/*
 * Auxiliary functions
 */
/* Hash derivation function based on SHA-512. Used by DRBG_SHA512 and
 * DRBG_DUAL_EC mechanism. */
int drbg_hash_df(const unsigned char *input_string,
		 size_t input_string_len,
		 unsigned char *req_bytes,
		 size_t req_bytes_len);

/* Obtain entropy input from an entropy source, a NRBG or another DRBG.
 * The request for prediciton resistence (@pr) rules out the use of a DRBG that
 * does not have access to either an entropy source or NRBG (see 9.). */
int drbg_get_entropy_input(bool pr,
			   int min_entropy,
			   size_t max_len,
			   unsigned char *entropy,
			   size_t entropy_len);

/* Obtain a nonce. The nonce is made of a timestamp, the thread id and a
 * counter */
int drbg_get_nonce(unsigned char *nonce,
		   size_t nonce_len);

/* Zeroise memory to erase sensitive data. */
static inline void drbg_zmem(void *ptr,
			     size_t len)
{
	if(ptr)
		memset(ptr, 0, len);

	/* protect this code from unwanted compiler optimization */
	__asm__ __volatile__ ("": :"r"(ptr) :"memory");
}

/* Check if memory area was zeroised. */
static inline int drbg_check_zmem(void *ptr,
				  size_t len)
{
	size_t i;

	if(!ptr)
		return DRBG_HEALTH_TEST_FAIL;

	for(i = 0; i < len; i++){
		if(((unsigned char *)ptr)[i])
			return DRBG_HEALTH_TEST_FAIL;
	}

	return 0;
}

/* Test whether a mechanism is valid. Returns EINVAL for unsupported
 * mechanisms, the error state (<0) for mechanisms in error state or 0 on
 * success. */
static inline int drbg_mech_valid(const ica_drbg_mech_t *mech)
{
	int i;

	if(!mech)
		return DRBG_MECH_INV;

	/* Check if @mech is supported. */
	for(i = DRBG_MECH_LIST_LEN - 1; i >= 0; i--){
		if(DRBG_MECH_LIST[i] == mech)
			break;
	}
	if(i < 0)
		return DRBG_MECH_INV;

	/* Check if @mech is in error state. */
	if(mech->error_state)
		return mech->error_state;

	return 0;
}


/* Initilize a recursive mutex. */
static inline void drbg_recursive_mutex_init(pthread_mutex_t *lock)
{
	pthread_mutexattr_t attr;

	pthread_mutexattr_init(&attr);
	pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(lock, &attr);
}

#endif
