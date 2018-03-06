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
 */

#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "s390_crypto.h"
#include "s390_drbg.h"
#include "s390_drbg_sha512.h"
#include "icastats.h"
#include "s390_sha.h"
#include "test_vec.h"

typedef struct drbg_sha512_ws ws_t; /* typedef for readability only */

/*
 * Auxiliary functions
 */
static int generate_add(ws_t *ws,
			const unsigned char *add,
			size_t add_len);

static int hashgen(const unsigned char *v,
		   unsigned char *prnd,
		   size_t prnd_len);

static int test_instantiate(int sec,
			    bool pr);

static int test_reseed(int sec,
		       bool pr);

static int test_generate(int sec,
			 bool pr);

/* Calculate @v = (@v + @s) mod 2 ^ (8 * DRBG_SHA512_SEED_LEN).
 * Make sure that @s_len <= v_len = DRBG_SHA512_SEED_LEN. */
static inline void mod_add(unsigned char *v,
			   const unsigned char *s,
			   size_t s_len)
{
	size_t i;
	uint16_t c = 0;

	v = v + DRBG_SHA512_SEED_LEN - 1;
	s = s + s_len - 1;

	for(i = 1; i <= s_len; i++, v--, s--)
		*v = (c = *v + *s + (uint8_t)(c >> 8));
	for(; i <= DRBG_SHA512_SEED_LEN; i++, v--)
		*v = (c = *v + (uint8_t)(c >> 8));
}

/*
 * SHA-512 DRBG mechanism
 */
ica_drbg_mech_t DRBG_SHA512 = {
	.id = "SHA-512",

	/* 10.1 Mechanisms Based on Hash Functions */
	.highest_supp_sec = DRBG_SEC_256,	/* = 256 bits */
	.seed_len = DRBG_SHA512_SEED_LEN,	/* = 888 bits */
	.max_pers_len = 256,			/* < 2^35 bits */
	.max_add_len = 256,			/* < 2^35 bits */
	.max_len = 256 - DRBG_NONCE_LEN,	/* < 2^35 bits */
	.max_no_of_bytes_per_req = 524288L / 8,	/* < 2^19 bits */
	.reseed_intervall = UINT32_MAX - 1,	/* < 2^48 */

	.instantiate = drbg_sha512_instantiate,
	.reseed = drbg_sha512_reseed,
	.generate = drbg_sha512_generate,
	.uninstantiate = drbg_sha512_uninstantiate,
	.health_test = drbg_sha512_health_test,

	/* Health test */
	.lock = PTHREAD_RWLOCK_INITIALIZER,
	.test_intervall = UINT64_MAX,
	.test_ctr = 0,
	.error_state = 0,
};

/*
 * SHA-512 DRBG mechanism functions
 *
 * No checks for invalid arguments are done here. The corresponding drbg_* -
 * functions are responsible for this.
 */
int drbg_sha512_instantiate_ppno(void **ws,
				 int sec,
				 const unsigned char *pers,
				 size_t pers_len,
				 const unsigned char *entropy,
				 size_t entropy_len,
				 const unsigned char *nonce,
				 size_t nonce_len)
{
	int status;

	(void)sec;	/* suppress unused param warning */

	/* 10.1.1.2 Hash_DRBG Instantiate Process */

	*ws = calloc(1, sizeof(ws_t)); /* buffer must be zero! (see POP) */
	if(!*ws)
		return DRBG_NOMEM;

	const size_t seed_material_len = entropy_len + nonce_len + pers_len;
	unsigned char seed_material[seed_material_len];

	/* step 1 */
	memcpy(seed_material, entropy, entropy_len);
	memcpy(seed_material + entropy_len, nonce, nonce_len);

	if(pers != NULL){
		memcpy(seed_material + entropy_len + nonce_len, pers,
		       pers_len);
	}

	/* steps 2 - 5 */
	status = s390_ppno(S390_CRYPTO_SHA512_DRNG_SEED, *ws, NULL, 0,
			   seed_material, seed_material_len);
	if(status)
		status = DRBG_HEALTH_TEST_FAIL;

	/* step 6 */
	drbg_zmem(seed_material, seed_material_len);
	return status;
}

int drbg_sha512_instantiate(void **ws,
			    int sec,
			    const unsigned char *pers,
			    size_t pers_len,
			    const unsigned char *entropy,
			    size_t entropy_len,
			    const unsigned char *nonce,
			    size_t nonce_len)
{
	const size_t seed_material_len = entropy_len + nonce_len + pers_len;
	unsigned char seed_material[seed_material_len];
	int status;

	(void)sec;	/* suppress unused param warning */

	/* 10.1.1.2 Hash_DRBG Instantiate Process */

	*ws = malloc(sizeof(ws_t));
	if(!*ws)
		return DRBG_NOMEM;

	unsigned char _0x00v[1 + sizeof(((ws_t *)*ws)->v)];

	/* step 1 */
	memcpy(seed_material, entropy, entropy_len);
	memcpy(seed_material + entropy_len, nonce, nonce_len);
	memcpy(seed_material + entropy_len + nonce_len, pers, pers_len);

	/* steps 2 and 3 */
	status = drbg_hash_df(seed_material, seed_material_len,
			      ((ws_t *)*ws)->v, sizeof(((ws_t *)*ws)->v));
	if(status){
		drbg_zmem(*ws, sizeof(ws_t));
		free(*ws);
		*ws = NULL;
		goto _exit_;
	}

	/* step 4 */
	_0x00v[0] = 0x00;
	memcpy(_0x00v + 1, ((ws_t *)*ws)->v, sizeof(((ws_t *)*ws)->v));

	status = drbg_hash_df(_0x00v, sizeof(_0x00v), ((ws_t *)*ws)->c,
			      sizeof(((ws_t *)*ws)->c));
	if(status){
		drbg_zmem(*ws, sizeof(ws_t));
		free(*ws);
		*ws = NULL;
		goto _exit_;
	}

	/* step 5 */
	((ws_t *)*ws)->reseed_ctr = 1;

	/* step 6 */
_exit_:
	drbg_zmem(_0x00v, sizeof(_0x00v));
	drbg_zmem(seed_material, seed_material_len);
	return status;
}

int drbg_sha512_reseed_ppno(void *ws,
			    const unsigned char *add,
			    size_t add_len,
			    const unsigned char *entropy,
			    size_t entropy_len)
{
	const size_t seed_material_len = entropy_len + add_len;
	unsigned char seed_material[seed_material_len];
	int status;

	/* 10.1.1.3 Hash_DRBG Reseed Process */

	/* step 1 (0x01||V is prepended by ppno, see POP)*/
	memcpy(seed_material, entropy, entropy_len);

	if(add != NULL){
		memcpy(seed_material + entropy_len, add, add_len);
	}

	/* steps 2 - 5 */
	status = s390_ppno(S390_CRYPTO_SHA512_DRNG_SEED, ws, NULL, 0,
			   seed_material, seed_material_len);
	if(status)
		status = DRBG_HEALTH_TEST_FAIL;

	/* step 6 */
	drbg_zmem(seed_material, seed_material_len);

	return status;
}

int drbg_sha512_reseed(void *ws,
		       const unsigned char *add,
		       size_t add_len,
		       const unsigned char *entropy,
		       size_t entropy_len)
{
	int status;
	unsigned char *seed_material;
	unsigned char _0x00v[1 + sizeof(((ws_t *)ws)->v)];
	const size_t seed_material_len = 1 + sizeof(((ws_t *)ws)->v)
					   + entropy_len + add_len;

	/* 10.1.1.3 Hash_DRBG Reseed Process */
	seed_material = malloc(seed_material_len);
	if(!seed_material)
		return DRBG_NOMEM;

	/* step 1 */
	seed_material[0] = 0x01;
	memcpy(seed_material + 1, ((ws_t *)ws)->v, sizeof(((ws_t *)ws)->v));
	memcpy(seed_material + 1 + sizeof(((ws_t *)ws)->v), entropy,
	       entropy_len);
	memcpy(seed_material + 1 + sizeof(((ws_t *)ws)->v) + entropy_len, add,
	       add_len);

	/* steps 2 and 3 */
	status = drbg_hash_df(seed_material, seed_material_len,
			      ((ws_t *)ws)->v, sizeof(((ws_t *)ws)->v));
	if(status)
		goto _exit_;

	/* step 4 */
	_0x00v[0] = 0x00;
	memcpy(_0x00v + 1, ((ws_t *)ws)->v, sizeof(((ws_t *)ws)->v));
	status = drbg_hash_df(_0x00v, sizeof(_0x00v), ((ws_t *)ws)->c,
			      sizeof(((ws_t *)ws)->c));
	if(status)
		goto _exit_;

	/* step 5 */
	((ws_t *)ws)->reseed_ctr = 1;

	/* step 6 */
_exit_:
	drbg_zmem(_0x00v, sizeof(_0x00v));
	drbg_zmem(seed_material, seed_material_len);
	free(seed_material);

	return status;
}

int drbg_sha512_generate_ppno(void *ws,
			      const unsigned char *add,
			      size_t add_len,
			      unsigned char *prnd,
			      size_t prnd_len)
{
	int status;

	/* increase corresponding icastats counter */
	stats_increment(ICA_STATS_DRBGSHA512, ALGO_HW, ENCRYPT);

	/* 10.1.1.4 Hash_DRBG Generate Process */

	/* step 1 */
	if(DRBG_SHA512.reseed_intervall < ((ws_t *)ws)->reseed_ctr)
		return DRBG_RESEED_REQUIRED;

	/* step 2 */
	if(add){
		status = generate_add(ws, add, add_len);
		if(status)
			return status;
	}

	/* steps 3 - 6 */
	status = s390_ppno(S390_CRYPTO_SHA512_DRNG_GEN, ws, prnd, prnd_len,
			   NULL, 0);
	if(status < 0 || (size_t)status != prnd_len)
		return DRBG_HEALTH_TEST_FAIL;

	/* step 7 */
	return 0;
}

int drbg_sha512_generate(void *ws,
			 const unsigned char *add,
			 size_t add_len,
			 unsigned char *prnd,
			 size_t prnd_len)
{
	unsigned char _0x03v[1 + sizeof(((ws_t *)ws)->v)] = {0};
	unsigned char h[DRBG_OUT_LEN];
	uint64_t shabuff[2];
	int status;

	/* increase corresponding icastats counter */
	stats_increment(ICA_STATS_DRBGSHA512, ALGO_SW, ENCRYPT);

	/* 10.1.1.4 Hash_DRBG Generate Process */

	/* step 1 */
	if(DRBG_SHA512.reseed_intervall < ((ws_t *)ws)->reseed_ctr)
		return DRBG_RESEED_REQUIRED;

	/* step 2 */
	if(add){
		status = generate_add(ws, add, add_len);
		if(status)
			return status;
	}

	/* step 3 */
	status = hashgen(((ws_t *)ws)->v, prnd, prnd_len);
	if(status)
		return status;

	/* step 4 */
	_0x03v[0] = 0x03;
	memcpy(_0x03v + 1, ((ws_t *)ws)->v, sizeof(((ws_t *)ws)->v));
	status = s390_sha_hw(SHA_512_DEFAULT_IV, _0x03v, sizeof(_0x03v), h,
				sha_constants[SHA_512].hash_length,
			    SHA_MSG_PART_ONLY, &shabuff[0], &shabuff[1],
			    SHA_512);
	if(status){
		status = DRBG_HEALTH_TEST_FAIL;
		goto _exit_;
	}

	/* step 5 */
	mod_add(((ws_t *)ws)->v, h, sizeof(h));
	mod_add(((ws_t *)ws)->v, ((ws_t *)ws)->c, sizeof(((ws_t *)ws)->c));
	mod_add(((ws_t *)ws)->v, (unsigned char *)&((ws_t *)ws)->reseed_ctr,
		sizeof(((ws_t *)ws)->reseed_ctr));

	/* step 6 */
	((ws_t *)ws)->reseed_ctr++;

	((ws_t *)ws)->stream_bytes += prnd_len; /* stay analogous to ppno */

	/* step 7 */
_exit_:
	drbg_zmem(_0x03v, sizeof(_0x03v));
	drbg_zmem(h, sizeof(h));
	return status;
}

int drbg_sha512_uninstantiate(void **ws,
			      bool test_mode)
{
	drbg_zmem((*ws), sizeof(ws_t));

	if(test_mode){
		int status = drbg_check_zmem(*ws, sizeof(ws_t));
		if(status)
			return status;
	}

	free(*ws);
	*ws = NULL;
	return 0;
}

int drbg_sha512_health_test(void *func,
			    int sec,
			    bool pr)
{
	static bool hw_check;

	/* Use ppno if available. */
	if(!hw_check){
		if(sha512_drng_switch){
			DRBG_SHA512.instantiate = drbg_sha512_instantiate_ppno;
			DRBG_SHA512.reseed = drbg_sha512_reseed_ppno;
			DRBG_SHA512.generate = drbg_sha512_generate_ppno;
		}
		else if(sha512_switch){
			DRBG_SHA512.instantiate = drbg_sha512_instantiate;
			DRBG_SHA512.reseed = drbg_sha512_reseed;
			DRBG_SHA512.generate = drbg_sha512_generate;
		}
		else
			return DRBG_HEALTH_TEST_FAIL;
		hw_check = true;
	}

	/* Health test. */
	if(drbg_instantiate == func)
		return test_instantiate(sec, pr);
	else if(drbg_reseed == func)
		return test_reseed(sec, pr);
	else if(drbg_generate == func)
		return test_generate(sec, pr);
	else
		return DRBG_REQUEST_INV;
}

/*
 * Auxiliary functions
 */
static int test_instantiate(int sec,
			    bool pr)
{
	ica_drbg_t *sh = NULL;
	const struct drbg_sha512_tv *tv;
	size_t i;
	int status;

	for(i = 0; i < DRBG_SHA512_TV_LEN; i++){
		tv = &DRBG_SHA512_TV[i];
		if(tv->pr != pr)
			continue;

		status = drbg_instantiate(&sh, sec, pr, &DRBG_SHA512,
					  tv->inst.pers, tv->pers_len, true,
					  tv->inst.nonce, tv->nonce_len,
					  tv->inst.entropy, tv->entropy_len);
		if(status)
			return status;

		if(memcmp(tv->inst.v, ((ws_t *)(sh->ws))->v,
			  DRBG_SHA512.seed_len) ||
		   memcmp(tv->inst.c, ((ws_t *)(sh->ws))->c,
			  DRBG_SHA512.seed_len) ||
		   tv->inst.reseed_ctr != ((ws_t *)(sh->ws))->reseed_ctr){
			drbg_uninstantiate(&sh, false);
			return DRBG_HEALTH_TEST_FAIL;
		}

		status = drbg_uninstantiate(&sh, false);
		if(status)
			return DRBG_HEALTH_TEST_FAIL;
	}

	return 0;
}

static int test_reseed(int sec,
		       bool pr)
{
	ws_t ws;
	ica_drbg_t sh = {.mech = &DRBG_SHA512, .ws = &ws, .sec = sec,
			 .pr = pr};
	const struct drbg_sha512_tv *tv;
	size_t i;
	int status;

	drbg_recursive_mutex_init(&sh.lock);

	for(i = 0; i < DRBG_SHA512_TV_LEN; i++){
		tv = &DRBG_SHA512_TV[i];
		if(tv->pr || tv->no_reseed)
			continue;

		memcpy(ws.v, tv->inst.v, DRBG_SHA512.seed_len);
		memcpy(ws.c, tv->inst.c, DRBG_SHA512.seed_len);
		ws.reseed_ctr = tv->inst.reseed_ctr;

		status = drbg_reseed(&sh, pr, tv->res.add, tv->add_len, true,
				     tv->res.entropy, tv->entropy_len);
		if(status)
			return status;

		if(memcmp(tv->res.v, ((ws_t *)sh.ws)->v,
			  DRBG_SHA512.seed_len) ||
		   memcmp(tv->res.c, ((ws_t *)sh.ws)->c,
			  DRBG_SHA512.seed_len) ||
		   tv->res.reseed_ctr != ((ws_t *)sh.ws)->reseed_ctr)
			return DRBG_HEALTH_TEST_FAIL;
	}

	return 0;
}

static int test_generate(int sec,
			 bool pr)
{
	ws_t ws;
	ica_drbg_t sh = {.mech = &DRBG_SHA512, .ws = &ws, .sec = sec,
			 .pr = true};
	size_t i;
	int status;
	const struct drbg_sha512_tv *tv;
	unsigned char prnd;

	drbg_recursive_mutex_init(&sh.lock);

	/* Use appropriate test vectors for self-test */
	do{
		for(i = 0; i < DRBG_SHA512_TV_LEN; i++){
			tv = &DRBG_SHA512_TV[i];
			if(tv->pr != pr)
				continue;

			if(!tv->no_reseed && !tv->pr){
				memcpy(ws.v, tv->res.v, DRBG_SHA512.seed_len);
				memcpy(ws.c, tv->res.c, DRBG_SHA512.seed_len);
				ws.reseed_ctr = tv->res.reseed_ctr;
			}
			else{
				memcpy(ws.v, tv->inst.v, DRBG_SHA512.seed_len);
				memcpy(ws.c, tv->inst.c, DRBG_SHA512.seed_len);
				ws.reseed_ctr = tv->inst.reseed_ctr;
			}

			unsigned char prnd[tv->prnd_len];
			status = drbg_generate(&sh, sec, pr, tv->gen1.add,
					       tv->add_len, true,
					       tv->gen1.entropy,
					       tv->entropy_len, prnd,
					       tv->prnd_len);
			if(status)
				return status;

			if(memcmp(tv->gen1.v, ((ws_t *)sh.ws)->v,
				  DRBG_SHA512.seed_len) ||
			   memcmp(tv->gen1.c, ((ws_t *)sh.ws)->c,
				  DRBG_SHA512.seed_len) ||
			   tv->gen1.reseed_ctr != ((ws_t *)sh.ws)->reseed_ctr)
				return DRBG_HEALTH_TEST_FAIL;

			status = drbg_generate(&sh, sec, pr, tv->gen2.add,
					       tv->add_len, true,
					       tv->gen2.entropy,
					       tv->entropy_len, prnd,
					       tv->prnd_len);
			if(status)
				return status;

			if(memcmp(tv->gen2.v, ((ws_t *)sh.ws)->v,
				  DRBG_SHA512.seed_len) ||
			   memcmp(tv->gen2.c, ((ws_t *)sh.ws)->c,
				  DRBG_SHA512.seed_len) ||
			   tv->gen2.reseed_ctr != ((ws_t *)sh.ws)->reseed_ctr)
				return DRBG_HEALTH_TEST_FAIL;

			if(memcmp(tv->prnd, prnd, tv->prnd_len))
				return DRBG_HEALTH_TEST_FAIL;
		}

		/* If pr = false, also run self-test with sh.pr = false. */
		if(pr || !sh.pr)
			break;
		else
			sh.pr = false;
	}while(true);

	/* Set reseed counter to meet the reseed intervall. */
	if(!pr){
		ws.reseed_ctr = DRBG_SHA512.reseed_intervall + 1;
		status = drbg_generate(&sh, sec, pr, NULL, 0, false, NULL, 0,
				       &prnd, sizeof(prnd));
		if(2 != ws.reseed_ctr)
			return DRBG_HEALTH_TEST_FAIL;
	}

	return 0;
}

static int generate_add(ws_t *ws,
			const unsigned char *add,
			size_t add_len)
{
	unsigned char *_0x02v;
	const size_t _0x02v_len = 1 + sizeof(ws->v) + add_len;
	unsigned char w[DRBG_OUT_LEN];
	uint64_t shabuff[2];
	int status;

	/* 10.1.1.4 Hash_DRBG Generate Process, step 2.x */

	/* step 2.1 */
	_0x02v = malloc(_0x02v_len);
	if(!_0x02v)
		return DRBG_NOMEM;
	_0x02v[0] = 0x02;
	memcpy(_0x02v + 1, ws->v, sizeof(ws->v));
	memcpy(_0x02v + 1 + sizeof(ws->v), add, add_len);
	status = s390_sha_hw(SHA_512_DEFAULT_IV, _0x02v, _0x02v_len, w,
				sha_constants[SHA_512].hash_length,
			    SHA_MSG_PART_ONLY, &shabuff[0], &shabuff[1],
			    SHA_512);
	if(status){
		status = DRBG_HEALTH_TEST_FAIL;
		goto _exit_;
	}

	/* step 2.2 */
	mod_add(ws->v, w, sizeof(w));

_exit_:
	drbg_zmem(w, DRBG_OUT_LEN);
	drbg_zmem(_0x02v, _0x02v_len);
	free(_0x02v);
	return status;
}

static int hashgen(const unsigned char *v,
		   unsigned char *prnd,
		   size_t prnd_len)
{
	unsigned char data[DRBG_SHA512_SEED_LEN];
	unsigned char w_i[DRBG_OUT_LEN];
	unsigned char *w;
	size_t m, i;
	uint64_t shabuff[2];
	int status;
	const unsigned char _0x01 = 0x01;

	/* 10.1.1.4 Hashgen Process */

	if(0 >= prnd_len)
		return 0; /* no pseudorandom bytes requested */

	/* step 1 */
	m = (prnd_len + DRBG_OUT_LEN - 1) / DRBG_OUT_LEN;

	/* step 2 */
	memcpy(data, v, sizeof(data));

	/* step 3 */
	w = malloc(m * DRBG_OUT_LEN);
	if(!w)
		return DRBG_NOMEM;

	/* step 4 */
	for(i = 1; i <= m; i++){
		status = s390_sha_hw(SHA_512_DEFAULT_IV, data, sizeof(data),
				     w_i, sha_constants[SHA_512].hash_length,
				     SHA_MSG_PART_ONLY, &shabuff[0],
				     &shabuff[1], SHA_512);
		if(status){
			status = DRBG_HEALTH_TEST_FAIL;
			goto _exit_;
		}
		memcpy(w + (i - 1) * DRBG_OUT_LEN, w_i, DRBG_OUT_LEN);
		mod_add(data, &_0x01, sizeof(_0x01));
	}

	/* step 5 */
	memcpy(prnd, w, prnd_len);

	/* step 6 */
_exit_:
	drbg_zmem(data, sizeof(data));
	drbg_zmem(w_i, DRBG_OUT_LEN);
	drbg_zmem(w, m * DRBG_OUT_LEN);
	free(w);
	return status;
}
