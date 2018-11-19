/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 *  Support for s390 cryptographic instructions.
 *
 *  Author(s): Thomas Spatzier
 *             Jan Glauber <jan.glauber@de.ibm.com>
 *             Ralph Wuerthner <rwuerthn@de.ibm.com>
 *	       Felix Beck <felix.beck@de.ibm.com>
 *	       Christian Maaser <cmaaser@de.ibm.com>
 *	       Holger Dengler <hd@linux.vnet.ibm.com>
 *	       Ingo Tuchscherer <ingo.tuchscherer.linux.vnet.ibm.com>
 *
 * Copyright IBM Corp. 2007, 2009, 2011, 2013
 */
#include <ica_api.h>

#ifndef S390_CRYPTO_H
#define S390_CRYPTO_H

#define S390_CRYPTO_TEST_MASK(mask, function) \
	(((unsigned char *)(mask))[((function) & 0x7F) >> 3] & \
	(0x80 >> ((function) & 0x07)))

#define KM	1
#define KMC	2
#define KIMD	3
#define MSA4	4
#define ADAPTER 5
#define PPNO	6
#define MSA8	7
#define MSA9	8

enum s390_crypto_instruction {
	S390_CRYPTO_DIRECTION_MASK = 0x80,
	S390_CRYPTO_FUNCTION_MASK = 0x7f
};

enum s390_crypto_function {
	/*
	 * The S390_QUERY function is always available for all 4 KM, KMC, KIMD and
	 * KLMD instructions and the PPNO instructions to query the available functions.
	 */
	S390_CRYPTO_QUERY = 0x00,
	/*
	 * The S390_SHA_* functions are available for KIMD and KLMD instructions.
	 */
	S390_CRYPTO_SHA_1 = 0x01,
	S390_CRYPTO_SHA_256 = 0x02,
	S390_CRYPTO_SHA_512 = 0x03,
	S390_CRYPTO_SHA_3_224 = 0x20,
	S390_CRYPTO_SHA_3_256 = 0x21,
	S390_CRYPTO_SHA_3_384 = 0x22,
	S390_CRYPTO_SHA_3_512 = 0x23,
	S390_CRYPTO_SHAKE_128 = 0x24,
	S390_CRYPTO_SHAKE_256 = 0x25,
	S390_CRYPTO_GHASH = 0x41,
	/*
	 * The following functions are available for KM,KMC,KMF,KMO,
	 * and KMCTR instructions.
	 */
	S390_CRYPTO_DEA_ENCRYPT = 0x01,
	S390_CRYPTO_DEA_DECRYPT = 0x01 | 0x80,
	S390_CRYPTO_TDEA_128_ENCRYPT = 0x02,
	S390_CRYPTO_TDEA_128_DECRYPT = 0x02 | 0x80,
	S390_CRYPTO_TDEA_192_ENCRYPT = 0x03,
	S390_CRYPTO_TDEA_192_DECRYPT = 0x03 | 0x80,
	S390_CRYPTO_AES_128_ENCRYPT = 0x12,
	S390_CRYPTO_AES_128_DECRYPT = 0x12 | 0x80,
	S390_CRYPTO_AES_192_ENCRYPT = 0x13,
	S390_CRYPTO_AES_192_DECRYPT = 0x13 | 0x80,
	S390_CRYPTO_AES_256_ENCRYPT = 0x14,
	S390_CRYPTO_AES_256_DECRYPT = 0x14 | 0x80,
	/* XTS is only available for the KM instruction */
	S390_CRYPTO_AES_128_XTS_ENCRYPT = 0x32,
	S390_CRYPTO_AES_128_XTS_DECRYPT = 0x32 | 0x80,
	S390_CRYPTO_AES_256_XTS_ENCRYPT = 0x34,
	S390_CRYPTO_AES_256_XTS_DECRYPT = 0x34 | 0x80,
	/* GCM */
	S390_CRYPTO_AES_128_GCM_ENCRYPT = 0x12,
	S390_CRYPTO_AES_128_GCM_DECRYPT = 0x12 | 0x80,
	S390_CRYPTO_AES_192_GCM_ENCRYPT = 0x13,
	S390_CRYPTO_AES_192_GCM_DECRYPT = 0x13 | 0x80,
	S390_CRYPTO_AES_256_GCM_ENCRYPT = 0x14,
	S390_CRYPTO_AES_256_GCM_DECRYPT = 0x14 | 0x80,

	/*
	 * The S390_PRNG is only available for the KMC instruction.
	 */
	S390_CRYPTO_PRNG = 0x43,
	/*
	 * The following functions are available for the PPNO/PRNO instruction.
	 */
	S390_CRYPTO_SHA512_DRNG_GEN  = 0x03,
	S390_CRYPTO_SHA512_DRNG_SEED = 0x03 | 0x80,
	S390_CRYPTO_TRNG	     = 0x72,

	/*
	 * The following functions are available for the KDSA instruction.
	 */
	S390_CRYPTO_ECDSA_VERIFY_P256 = 0x01,
	S390_CRYPTO_ECDSA_VERIFY_P384 = 0x02,
	S390_CRYPTO_ECDSA_VERIFY_P521 = 0x03,
	S390_CRYPTO_ECDSA_SIGN_P256 = 0x09,
	S390_CRYPTO_ECDSA_SIGN_P384 = 0x0a,
	S390_CRYPTO_ECDSA_SIGN_P521 = 0x0b,
	S390_CRYPTO_EDDSA_VERIFY_ED25519 = 0x20,
	S390_CRYPTO_EDDSA_VERIFY_ED448 = 0x24,
	S390_CRYPTO_EDDSA_SIGN_ED25519 = 0x28,
	S390_CRYPTO_EDDSA_SIGN_ED448 = 0x2c,

	/*
	 * The following functions are available for the PCC instruction.
	 */
	S390_CRYPTO_SCALAR_MULTIPLY_P256 = 0x40,
	S390_CRYPTO_SCALAR_MULTIPLY_P384 = 0x41,
	S390_CRYPTO_SCALAR_MULTIPLY_P521 = 0x42,
	S390_CRYPTO_SCALAR_MULTIPLY_ED25519 = 0x48,
	S390_CRYPTO_SCALAR_MULTIPLY_ED448 = 0x49,
	S390_CRYPTO_SCALAR_MULTIPLY_X25519 = 0x50,
	S390_CRYPTO_SCALAR_MULTIPLY_X448 = 0x51
};

extern unsigned long long facility_bits[3];
extern unsigned int sha1_switch, sha256_switch, sha512_switch, sha3_switch, des_switch,
	     tdes_switch, aes128_switch, aes192_switch, aes256_switch,
	     prng_switch, tdea128_switch, tdea192_switch, sha512_drng_switch,
	     msa4_switch, msa5_switch, msa8_switch, trng_switch, msa9_switch;

typedef struct {
	unsigned int dummy_fc;
	unsigned int hw_fc;
	unsigned int *enabled;
} s390_supported_function_t;

/* Append new dummy fc codes to the end of enumeration. They are used as index
 * to get the right fc code for the hardware. */
typedef enum {
	SHA_1,
	SHA_224,
	SHA_256,
	SHA_384,
	SHA_512,
	SHA_3_224,
	SHA_3_256,
	SHA_3_384,
	SHA_3_512,
	SHAKE_128,
	SHAKE_256,
	GHASH,
	SHA_512_224,
	SHA_512_256
} kimd_functions_t;

typedef enum {
	CMAC_AES_128_GENERATE,
	CMAC_AES_128_VERIFY,
	CMAC_AES_192_GENERATE,
	CMAC_AES_192_VERIFY,
	CMAC_AES_256_GENERATE,
	CMAC_AES_256_VERIFY,
	SCALAR_MULTIPLY_P256,
	SCALAR_MULTIPLY_P384,
	SCALAR_MULTIPLY_P521,
	SCALAR_MULTIPLY_ED25519,
	SCALAR_MULTIPLY_ED448,
	SCALAR_MULTIPLY_X25519,
	SCALAR_MULTIPLY_X448
} pcc_functions_t;

typedef enum {
	SHA512_DRNG_GEN,
	SHA512_DRNG_SEED,
	TRNG
} ppno_functions_t;

extern s390_supported_function_t s390_kmc_functions[];
extern s390_supported_function_t s390_msa4_functions[];
extern s390_supported_function_t s390_pcc_functions[];
extern s390_supported_function_t s390_kma_functions[];
extern s390_supported_function_t s390_kimd_functions[];
extern s390_supported_function_t s390_ppno_functions[];
extern s390_supported_function_t s390_kdsa_functions[];

void s390_crypto_switches_init(void);

/**
 * s390_pcc:
 * @func: the function code passed to KM; see s390_pcc_functions
 * @param: address of parameter block; see POP for details on each func
 *
 * Executes the PCC operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static inline int s390_pcc(unsigned long func, void *param)
{
	register unsigned long r0 asm("0") = (unsigned long)func;
	register unsigned long r1 asm("1") = (unsigned long)param;

	asm volatile (
		"0:	.long	%[opc] << 16\n"
		"	brc	1,0b\n"
		:
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb92c)
		: "cc", "memory");

	return 0;
}

/**
 * s390_kmac:
 * @func: the function code passed to KMAC; see s390_kmac_func
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KMAC (COMPUTE MESSAGE AUTHENTICATION CODE) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static inline int s390_kmac(unsigned long func, void *param,
		    const unsigned char *src, long src_len)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;

	asm volatile (
		"0:     .insn   rre, 0xb91e0000,%0,%0 \n"
		"       brc     1, 0b \n"
		: "+a"(__src), "+d"(__src_len)
		: "d"(__func), "a"(__param)
		: "cc", "memory");
	return func ? src_len - __src_len : __src_len;
}

/**
 * s390_kma:
 * @func: the function code passed to KMA; see s390_kma_functions
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 * @aad: address of optional additional authenticated data
 * @aad_len: length of aad operand in bytes
 *
 * Executes the KMA (CIPHER MESSAGE WITH AUTHENTICATION) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static inline int s390_kma(unsigned long func, void *param, unsigned char *dest,
		      const unsigned char *src, long src_len,
		      const unsigned char *aad, long aad_len)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;
	register unsigned char *__dest asm("4") = dest;
	register const unsigned char *__aad asm("6") = aad;
	register long __aad_len asm("7") = aad_len;

	asm volatile(
		"0:	.insn	rrf,0xb9290000,%2,%0,%3,0 \n"
		"1:	brc	1,0b \n" /* handle partial completion */
		: "+a" (__src), "+d" (__src_len), "+a" (__dest), "+a" (__aad), "+d" (__aad_len)
		: "d" (__func), "a" (__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

/**
 * s390_kmctr:
 * @func: the function code passed to KMCTR; see s390_km_func
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KMCTR (CIPHER MESSAGE WITH COUNTER) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static inline int s390_kmctr(unsigned long func, void *param, unsigned char *dest,
		      const unsigned char *src, long src_len,
		      unsigned char *counter)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;
	register unsigned char *__dest asm("4") = dest;
	register unsigned char *__ctr asm("6") = counter;

	asm volatile(
		"0:	.insn	rrf,0xb92d0000,%2,%0,%3,0 \n"
		"1:	brc	1,0b \n"
		: "+a" (__src), "+d" (__src_len), "+a" (__dest), "+a" (__ctr)
		: "d" (__func), "a" (__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

/**
 * s390_kmf:
 * @func: the function code passed to KMF; see s390_kmf_func
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KMF (CIPHER MESSAGE) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static inline int s390_kmf(unsigned long func, void *param, unsigned char *dest,
		   const unsigned char *src, long src_len, unsigned int *lcfb)
{
	register long __func asm("0") = ((*lcfb & 0x000000ff) << 24) | func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;
	register unsigned char *__dest asm("4") = dest;

	asm volatile (
		"0:	.insn	rre,0xb92a0000,%2,%0 \n"
		"	brc	1,0b \n"
		: "+a"(__src), "+d"(__src_len), "+a"(__dest)
		: "d"(__func), "a"(__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

/**
 * s390_kmo:
 * @func: the function code passed to KMO; see s390_kmc_func
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KMO (CIPHER MESSAGE WITH CHAINING) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static inline int s390_kmo(unsigned long func, void *param, unsigned char *dest,
		    const unsigned char *src, long src_len)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;
	register unsigned char *__dest asm("4") = dest;

	asm volatile (
		"0:	.insn	rre, 0xb92b0000,%2,%0 \n"
		"	brc	1, 0b \n"
		: "+a"(__src), "+d"(__src_len), "+a"(__dest)
		: "d"(__func), "a"(__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

/**
 * s390_km:
 * @func: the function code passed to KM; see s390_km_func
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KM (CIPHER MESSAGE) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static inline int s390_km(unsigned long func, void *param, unsigned char *dest,
		   const unsigned char *src, long src_len)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;
	register unsigned char *__dest asm("4") = dest;

	asm volatile (
		"0:	.insn	rre,0xb92e0000,%2,%0 \n"	/* KM opcode */
		"	brc	1,0b \n"	/* handle partial completion */
		: "+a"(__src), "+d"(__src_len), "+a"(__dest)
		: "d"(__func), "a"(__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

/**
 * s390_kmc:
 * @func: the function code passed to KM; see s390_kmc_func
 * @param: address of parameter block; see POP for details on each func
 * @dest: address of destination memory area
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KMC (CIPHER MESSAGE WITH CHAINING) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
static inline int s390_kmc(unsigned long func, void *param, unsigned char *dest,
		    const unsigned char *src, long src_len)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;
	register unsigned char *__dest asm("4") = dest;

	asm volatile (
		"0:	.insn	rre, 0xb92f0000,%2,%0 \n"	/* KMC opcode */
		"	brc	1, 0b \n"	/* handle partial completion */
		: "+a"(__src), "+d"(__src_len), "+a"(__dest)
		: "d"(__func), "a"(__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

/**
 * s390_kimd:
 * @func: the function code passed to KM; see s390_kimd_func
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KIMD (COMPUTE INTERMEDIATE MESSAGE DIGEST) operation
 * of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for digest funcs
 */
static inline int s390_kimd_shake(unsigned long func, void *param,
		unsigned char *dest, long dest_len,
	     const unsigned char *src, long src_len)
{
	register long  __func asm("0") = func;
	register void *__param asm("1") = param;
	register unsigned char *__dest asm("2") = dest;
	register long  __dest_len asm("3") = dest_len;
	register const unsigned char *__src asm("4") = src;
	register long  __src_len asm("5") = src_len;
	int ret = -1;

	asm volatile(
		"0:      .insn   rre,0xb93e0000,%1,%5\n\t" /* KIMD opcode */
		"        brc     1,0b\n\t" /* handle partial completion */
		"        la      %0,0\n\t"
		: "+d" (ret), "+a"(__dest), "+d"(__dest_len)
		: "d"(__func), "a"(__param), "a"(__src), "d"(__src_len)
		: "cc", "memory"
	);

	return func ? src_len - __src_len : __src_len;
}

static inline int s390_kimd(unsigned long func, void *param,
		     const unsigned char *src, long src_len)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;

	asm volatile (
		"0:	.insn	rre,0xb93e0000,%0,%0 \n"	/* KIMD opcode */
		"	brc	1,0b \n"	/* handle partial completion */
		: "+a"(__src), "+d"(__src_len)
		: "d"(__func), "a"(__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

/**
 * s390_klmd:
 * @func: the function code passed to KM; see s390_klmd_func
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @src_len: length of src operand in bytes
 *
 * Executes the KLMD (COMPUTE LAST MESSAGE DIGEST) operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for digest funcs
 */
static inline int s390_klmd_shake(unsigned long func, void *param,
		unsigned char *dest, long dest_len,
		const unsigned char *src, long src_len)
{
	register long  __func asm("0") = func;
	register void *__param asm("1") = param;
	register unsigned char *__dest asm("2") = dest;
	register long  __dest_len asm("3") = dest_len;
	register const unsigned char *__src asm("4") = src;
	register long  __src_len asm("5") = src_len;
	int ret = -1;

	asm volatile(
		"0:      .insn   rre,0xb93f0000,%1,%5\n\t" /* KLMD opcode */
		"        brc     1,0b\n\t" /* handle partial completion */
		"        la      %0,0\n\t"
		: "+d" (ret), "+a"(__dest), "+d"(__dest_len)
		: "d"(__func), "a"(__param), "a"(__src), "d"(__src_len)
		: "cc", "memory"
	);

	return func ? src_len - __src_len : __src_len;
}

static inline int s390_klmd(unsigned long func, void *param,
		const unsigned char *src, long src_len)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;

	asm volatile (
		"0:	.insn	rre,0xb93f0000,%0,%0 \n" /* KLMD opcode */
		"	brc	1,0b \n"	/* handle partial completion */
		: "+a"(__src), "+d"(__src_len)
		: "d"(__func), "a"(__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}
/**
 * s390_kdsa:
 * @func: the function code passed to KDSA; see s390_kdsa_functions
 * @param: address of parameter block; see POP for details on each func
 * @src: address of source memory area
 * @srclen: length of src operand in bytes
 *
 * Executes the KDSA (COMPUTE DIGITAL SIGNATURE AUTHENTICATION) operation of
 * the CPU.
 *
 * Returns 0 on success. Fails in case of sign if the random number was not
 * invertible. Fails in case of verify if the signature is invalid or the
 * public key is not on the curve.
 */
static inline int s390_kdsa(unsigned long func, void *param,
		            const unsigned char *src, unsigned long srclen)
{
	register unsigned long r0 asm("0") = (unsigned long)func;
	register unsigned long r1 asm("1") = (unsigned long)param;
	register unsigned long r2 asm("2") = (unsigned long)src;
	register unsigned long r3 asm("3") = (unsigned long)srclen;

	unsigned long rc = 1;

	asm volatile(
		"0:	.insn	rre,%[opc] << 16,0,%[src]\n"
		"	brc	1,0b\n" /* handle partial completion */
		"	brc	7,1f\n"
		"	lghi	%[rc],0\n"
		"1:\n"
		: [src] "+a" (r2), [srclen] "+d" (r3), [rc] "+d" (rc)
		: [fc] "d" (r0), [param] "a" (r1), [opc] "i" (0xb93a)
		: "cc", "memory");

	return (int)rc;
}

/*
 * s390_ppno:
 *
 * @func: FUNction code. See s390_ppno_func.
 * @param: PARAMeter block.
 * @dest: DESTination. Address of destination memory area.
 * @dest_len: Byte length of @dest
 * @src: SouRCe. Address of source memory area.
 * @src_len: Byte length of @src
 *
 * Executes the PPNO (Perform Pseudorandom Number Operation) operation of the
 * CPU. See POP for details.
 *
 * @return:
 * -1					Failure.
 * 0					Success.
 * no. of processed bytes
 */
static inline int s390_ppno(long func,
			    void *param,
			    unsigned char *dest,
			    long dest_len,
			    const unsigned char *src,
			    long src_len)
{
	register long  __func asm("0") = func;
	register void *__param asm("1") = param;
	register unsigned char *__dest asm("2") = dest;
	register long  __dest_len asm("3") = dest_len;
	register const unsigned char *__src asm("4") = src;
	register long  __src_len asm("5") = src_len;
	int ret = -1;

	asm volatile(
		"0:      .insn   rre,0xb93c0000,%1,%5\n\t" /* PPNO opcode */
		"        brc     1,0b\n\t" /* handle partial completion */
		"        la      %0,0\n\t"
		: "+d" (ret), "+a"(__dest), "+d"(__dest_len)
		: "d"(__func), "a"(__param), "a"(__src), "d"(__src_len)
		: "cc", "memory"
	);

	if(ret < 0)
		return ret;

	return func ? dest_len - __dest_len : 0;
}

/**
 * cpacf_trng() - executes the TRNG subfunction of the PRNO instruction
 * @ucbuf: buffer for unconditioned data
 * @ucbuf_len: amount of unconditioned data to fetch in bytes
 * @cbuf: buffer for conditioned data
 * @cbuf_len: amount of conditioned data to fetch in bytes
 */
static inline void cpacf_trng(unsigned char *ucbuf, unsigned long ucbuf_len,
                              unsigned char *cbuf, unsigned long cbuf_len)
{
        register unsigned long r0 asm("0") = (unsigned long) S390_CRYPTO_TRNG;
        register unsigned long r2 asm("2") = (unsigned long) ucbuf;
        register unsigned long r3 asm("3") = (unsigned long) ucbuf_len;
        register unsigned long r4 asm("4") = (unsigned long) cbuf;
        register unsigned long r5 asm("5") = (unsigned long) cbuf_len;

        asm volatile (
                "0:     .insn   rre,0xb93c0000,%[ucbuf],%[cbuf]\n"
                "       brc     1,0b\n"   /* handle partial completion */
                : [ucbuf] "+a" (r2), [ucbuflen] "+d" (r3),
                  [cbuf] "+a" (r4), [cbuflen] "+d" (r5)
                : [fc] "d" (r0)
                : "cc", "memory");
}


static inline void s390_stckf_hw(void *buf)
{
	asm volatile(".insn     s,0xb27c0000,%0"
		     : "=Q" (*((unsigned long long *)buf)) : : "cc");
}

static inline void s390_stcke_hw(void *buf)
{
	asm volatile(".insn     s,0xb2780000,%0"
		     : "=Q" (*((unsigned long long *)buf)) : : "cc");
}

static inline int __stfle(unsigned long long *list, int doublewords)
{
	register unsigned long __nr asm("0") = doublewords - 1;

	asm volatile(".insn s,0xb2b00000,0(%1)" /* stfle */
		     : "+d" (__nr) : "a" (list) : "memory", "cc");

	return __nr + 1;
}

#endif

