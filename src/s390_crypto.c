/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Entry point for crypto graphic instructions on s390. If a instruction
 * is not available, instruction will be simulated in software.
 *
 * Authors(s): Ralph Wuerthner <rwuerthn@de.ibm.com>
 *	       Jan Glauber <jan.glauber@de.ibm.com>
 *	       Felix Beck <felix.beck@de.ibm.com>
 *	       Christian Maaser <cmaaser@de.ibm.com>
 *	       Holger Dengler <hd@linux.vnet.ibm.com>
 *	       Ingo Tuchscherer <ingo.tuchscherer.linux.vnet.ibm.com>
 *
 * Copyright IBM Copr. 2007, 2009, 2011, 2013
 */

#include <stdint.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "s390_crypto.h"
#include "init.h"

s390_supported_function_t s390_kimd_functions[] = {
	{SHA_1, S390_CRYPTO_SHA_1, &sha1_switch},
	{SHA_224, S390_CRYPTO_SHA_256, &sha256_switch},
	{SHA_256, S390_CRYPTO_SHA_256, &sha256_switch},
	{SHA_384, S390_CRYPTO_SHA_512, &sha512_switch},
	{SHA_512, S390_CRYPTO_SHA_512, &sha512_switch},
	{GHASH, S390_CRYPTO_GHASH, &msa4_switch}
};

s390_supported_function_t s390_kmc_functions[] = {
	{DEA_ENCRYPT, S390_CRYPTO_DEA_ENCRYPT, &des_switch},
	{DEA_DECRYPT, S390_CRYPTO_DEA_DECRYPT, &des_switch},
	{TDEA_192_ENCRYPT, S390_CRYPTO_TDEA_192_ENCRYPT, &tdes_switch},
	{TDEA_192_DECRYPT, S390_CRYPTO_TDEA_192_DECRYPT, &tdes_switch},
	{AES_128_ENCRYPT, S390_CRYPTO_AES_128_ENCRYPT, &aes128_switch},
	{AES_128_DECRYPT, S390_CRYPTO_AES_128_DECRYPT, &aes128_switch},
	{AES_192_ENCRYPT, S390_CRYPTO_AES_192_ENCRYPT, &aes192_switch},
	{AES_192_DECRYPT, S390_CRYPTO_AES_192_DECRYPT, &aes192_switch},
	{AES_256_ENCRYPT, S390_CRYPTO_AES_256_ENCRYPT, &aes256_switch},
	{AES_256_DECRYPT, S390_CRYPTO_AES_256_DECRYPT, &aes256_switch},
	{AES_128_XTS_ENCRYPT, S390_CRYPTO_AES_128_XTS_ENCRYPT, &msa4_switch},
	{AES_128_XTS_DECRYPT, S390_CRYPTO_AES_128_XTS_DECRYPT, &msa4_switch},
	{AES_256_XTS_ENCRYPT, S390_CRYPTO_AES_256_XTS_ENCRYPT, &msa4_switch},
	{AES_256_XTS_DECRYPT, S390_CRYPTO_AES_256_XTS_DECRYPT, &msa4_switch},
	{PRNG, S390_CRYPTO_PRNG, &prng_switch}
};

s390_supported_function_t s390_msa4_functions[] = {
	{DEA_ENCRYPT, S390_CRYPTO_DEA_ENCRYPT, &msa4_switch},
	{DEA_DECRYPT, S390_CRYPTO_DEA_DECRYPT, &msa4_switch},
	{TDEA_192_ENCRYPT, S390_CRYPTO_TDEA_192_ENCRYPT, &msa4_switch},
	{TDEA_192_DECRYPT, S390_CRYPTO_TDEA_192_DECRYPT, &msa4_switch},
	{AES_128_ENCRYPT, S390_CRYPTO_AES_128_ENCRYPT, &msa4_switch},
	{AES_128_DECRYPT, S390_CRYPTO_AES_128_DECRYPT, &msa4_switch},
	{AES_192_ENCRYPT, S390_CRYPTO_AES_192_ENCRYPT, &msa4_switch},
	{AES_192_DECRYPT, S390_CRYPTO_AES_192_DECRYPT, &msa4_switch},
	{AES_256_ENCRYPT, S390_CRYPTO_AES_256_ENCRYPT, &msa4_switch},
	{AES_256_DECRYPT, S390_CRYPTO_AES_256_DECRYPT, &msa4_switch},
	{AES_128_XTS_ENCRYPT, S390_CRYPTO_AES_128_XTS_ENCRYPT, &msa4_switch},
	{AES_128_XTS_DECRYPT, S390_CRYPTO_AES_128_XTS_DECRYPT, &msa4_switch},
	{AES_256_XTS_ENCRYPT, S390_CRYPTO_AES_256_XTS_ENCRYPT, &msa4_switch},
	{AES_256_XTS_DECRYPT, S390_CRYPTO_AES_256_XTS_DECRYPT, &msa4_switch}
};

/**
 * s390_pcc:
 * @func: the function code passed to KM; see s390_kmc_func
 * @param: address of parameter block; see POP for details on each func
 *
 * Executes the PCC operation of the CPU.
 *
 * Returns -1 for failure, 0 for the query func, number of processed
 * bytes for encryption/decryption funcs
 */
inline int s390_pcc(unsigned long func, void *param)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;

	asm volatile (
		"0: .long 0xb92c0000 \n"
		"	brc	1, 0b \n"
		:
		: "d"(__func), "a"(__param)
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
inline int s390_kmac(unsigned long func, void *param,
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
inline int s390_kmctr(unsigned long func, void *param, unsigned char *dest,
		      unsigned char *src, long src_len,
		      unsigned char *counter)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register unsigned char *__src asm("2") = src;
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
inline int s390_kmf(unsigned long func, void *param, unsigned char *dest,
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
inline int s390_kmo(unsigned long func, void *param, unsigned char *dest,
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
inline int s390_km(unsigned long func, void *param, unsigned char *dest,
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
inline int s390_kmc(unsigned long func, void *param, unsigned char *dest,
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
inline int s390_kimd(unsigned long func, void *param,
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
inline int s390_klmd(unsigned long func, void *param, const unsigned char *src,
		     long src_len)
{
	register long __func asm("0") = func;
	register void *__param asm("1") = param;
	register const unsigned char *__src asm("2") = src;
	register long __src_len asm("3") = src_len;

	asm volatile (
		"0:	.insn	rre,0xb93f0000,%0,%0 \n"	/* KLMD opcode */
		"	brc	1,0b \n"	/* handle partial completion */
		: "+a"(__src), "+d"(__src_len)
		: "d"(__func), "a"(__param)
		: "cc", "memory");

	return func ? src_len - __src_len : __src_len;
}

int s390_stckf_hw(void *buf)
{
	register int cc = 0;

	asm volatile(".insn     s,0xb27c0000,%0"
		     : "=m" (*((unsigned long long *)buf)) : : "cc");
	return cc;
}

int s390_stcke_hw(void *buf)
{
	register int cc = 0;

	asm volatile(".insn     s,0xb2780000,%0"
		     : "=m" (*((unsigned long long *)buf)) : : "cc");
	return cc;
}

inline int s390_stck(void *buf)
{
#ifdef _LINUX_S390X_
	return s390_stckf_hw(buf);
#endif
	return s390_stcke_hw(buf);
}

static inline int __stfle(unsigned long long *list, int doublewords)
{
        typedef struct { unsigned long long _[doublewords]; } addrtype;
        register unsigned long __nr asm("0") = doublewords - 1;

        asm volatile(".insn s,0xb2b00000,%0" /* stfle */
                     : "=m" (*(addrtype *) list), "+d" (__nr) : : "cc");
        return __nr + 1;
}

int read_cpuinfo(void)
{
	int msa = 0;
	FILE *handle = fopen("/proc/cpuinfo", "r");
	if (handle) {
		char buffer[80];
		int i = 0;
		while(fgets(buffer, sizeof(buffer), handle)) {
			i++;
			if(strstr(buffer,"features") && strstr(buffer,"msa")) {
				msa = 1;
				break;
			}
		}
		fclose(handle);
	}
	return msa;
}

int read_facility_bits(void)
{
	int msa = 0;
	unsigned long long facility_bits[2];
	struct sigaction oldact;
	sigset_t oldset;
	int rc = -1;
	rc = begin_sigill_section(&oldact, &oldset);
	if (!rc) {
		rc = __stfle(facility_bits, 2);
		end_sigill_section(&oldact, &oldset);
	}
	if (rc == 2) {
		// stfle should return 2
		if(facility_bits[0] & (1ULL << (63 - 17)))
			msa = 1;
		if(facility_bits[1] & (1ULL << (127 - 77)))
			msa = 4;
	}
	return msa;
}

void set_switches(int msa)
{
	unsigned char mask[16];
	unsigned int n;
	unsigned int on = 0;
	struct sigaction oldact;
	sigset_t oldset;
	/* The function arrays contain integers. Thus to compute the amount of
	 * their elements the result of sizeof(*functions) has to be divided by
	 * sizeof(int).
	 * The msa4_switch will be set in the kimd function. Because this is
	 * the only switch for all MSA4 functions we just set it through the
	 * kimd query and do not need to over the whole array. Therfore there
	 * is also no distict setting of the switch needed in form
	 * msa4_switch = 1. */
	memset(mask, 0, sizeof(mask));
	if (msa) {
		if (begin_sigill_section(&oldact, &oldset) == 0) {
			s390_kmc(S390_CRYPTO_QUERY, mask, (void *) 0, (void *) 0, 0);
		        end_sigill_section(&oldact, &oldset);
		}
	}
	for (n = 0; n < (sizeof(s390_kmc_functions) /
			 sizeof(s390_supported_function_t)); n++) {
		if (S390_CRYPTO_TEST_MASK(mask, s390_kmc_functions[n].hw_fc))
			on = 1;
		else
			on = 0;
		*s390_kmc_functions[n].enabled = on;
	}

	if (msa) {
		if (begin_sigill_section(&oldact, &oldset) == 0) {
			s390_kimd(S390_CRYPTO_QUERY, mask, (void *) 0, 0);
			end_sigill_section(&oldact, &oldset);
		}
	}

	for (n = 0; n < (sizeof(s390_kimd_functions) /
			 sizeof(s390_supported_function_t)); n++) {
		if (S390_CRYPTO_TEST_MASK(mask, s390_kimd_functions[n].hw_fc))
	        on = 1;
	else
	        on = 0;
		*s390_kimd_functions[n].enabled = on;
	}
}

void s390_crypto_switches_init(void)
{
	/* First read cpu info to check if msa feature is available.
	 * If it is not available, execute stfle instructions to read the
	 * facility bits.
	 * If then crypto support is detected crypto functions will be queryed
	 * from the processor */
	int msa;
	msa = read_cpuinfo();

	msa = read_facility_bits();
	if (!msa)
		msa = read_cpuinfo();

	set_switches(msa);
}

/*
 * The first field represents the mechanism ID.
 * The second field represents the function family type (category), 
 * The third filed represents the function code.
 * This function code will be used later to check if HW support 
 * is available and modifies the SW/HW-support-flag.
 * SHW - static hardware support (CPACF) 
 * DHW - dynamic hardware support (crypto adapter)
 * SW  - software support
 * Bit field flags: [0|0|0|0|0|SHW|DHW|SW]
 * The last filed represent the property flags
 */
libica_func_list_element_int icaList[] = {
 {SHA1,   KIMD, SHA_1  		, ICA_FLAG_SW, 0},
 {SHA224, KIMD, SHA_256		, ICA_FLAG_SW, 0},
 {SHA256, KIMD, SHA_256		, ICA_FLAG_SW, 0},
 {SHA384, KIMD, SHA_512		, ICA_FLAG_SW, 0},
 {SHA512, KIMD, SHA_512		, ICA_FLAG_SW, 0},

 {DES_ECB,      KMC,  DEA_ENCRYPT, ICA_FLAG_SW, 0},
 {DES_CBC,      KMC,  DEA_ENCRYPT, ICA_FLAG_SW, 0},
 {DES_CBC_CS,   MSA4, DEA_ENCRYPT, 0, 0},
 {DES_OFB,      MSA4, DEA_ENCRYPT, 0, 0},
 {DES_CFB,      MSA4, DEA_ENCRYPT, 0, 0},
 {DES_CTR,      MSA4, DEA_ENCRYPT, 0, 0},
 {DES_CTRLST,   MSA4, DEA_ENCRYPT, 0, 0},
 {DES_CBC_MAC,  MSA4, DEA_ENCRYPT, 0, 0},					// CPACF only (MSA4)
 {DES_CMAC,     MSA4, DEA_ENCRYPT, 0, 0},					// CPACF only (MSA4)
 //{DES_KEY_GEN,  MSA4, DEA_ENCRYPT, 0, 0},					// CPACF only (MSA4)
 
 {DES3_ECB,     KMC,  TDEA_192_ENCRYPT, ICA_FLAG_SW, 0},
 {DES3_CBC,     KMC,  TDEA_192_ENCRYPT, ICA_FLAG_SW, 0},
 {DES3_CBC_CS,  MSA4, TDEA_192_ENCRYPT,           0, 0},
 {DES3_OFB,     MSA4, TDEA_192_ENCRYPT,           0, 0},
 {DES3_CFB,     MSA4, TDEA_192_ENCRYPT, 	  	  0, 0},
 {DES3_CTR,     MSA4, TDEA_192_ENCRYPT,           0, 0},
 {DES3_CTRLST,  MSA4, TDEA_192_ENCRYPT,           0, 0},
 {DES3_CBC_MAC, MSA4, TDEA_192_ENCRYPT,           0, 0},
 {DES3_CMAC,    MSA4, TDEA_192_ENCRYPT,           0, 0},
 //{DES3_KEY_GEN, MSA4, TDEA_192_ENCRYPT,           0, 0},
  
 {AES_ECB,      KMC,  AES_128_ENCRYPT, ICA_FLAG_SW, 0}, 
 {AES_CBC,      KMC,  AES_128_ENCRYPT, ICA_FLAG_SW, 0},
 {AES_CBC_CS,   MSA4, AES_128_ENCRYPT,           0, 0},
 {AES_OFB,      MSA4, AES_128_ENCRYPT,           0, 0},
 {AES_CFB,      MSA4, AES_128_ENCRYPT,           0, 0},
 {AES_CTR,      MSA4, AES_128_ENCRYPT,           0, 0},
 {AES_CTRLST,   MSA4, AES_128_ENCRYPT,           0, 0},
 {AES_CBC_MAC,  MSA4, AES_128_ENCRYPT,           0, 0},
 {AES_CMAC,     MSA4, AES_128_ENCRYPT,           0, 0},
 //{AES_KEY_GEN,     MSA4, AES_128_ENCRYPT,        0, 0},
 {AES_CCM,      MSA4, AES_128_ENCRYPT, 	         0, 0},
 {AES_GCM,      MSA4, AES_128_ENCRYPT,           0, 0},
 {AES_XTS,      MSA4, AES_128_XTS_ENCRYPT,       0, 0},
 {P_RNG,    		ADAPTER, 0, ICA_FLAG_SHW | ICA_FLAG_SW, 0},	// SHW (CPACF) + SW
 {RSA_ME, 		ADAPTER, 0, ICA_FLAG_DHW | ICA_FLAG_SW, 0x0F},	// DHW (CEX) + SW / 512,1024,2048, 4096 bit key length
 {RSA_CRT, 		ADAPTER, 0, ICA_FLAG_DHW | ICA_FLAG_SW, 0x0F},	// DHW (CEX) + SW / 512,1024,2048, 4096 bit key length
 {RSA_KEY_GEN_ME,  	ADAPTER, 0, ICA_FLAG_SW, 		0},	// SW (openssl)
 {RSA_KEY_GEN_CRT, 	ADAPTER, 0, ICA_FLAG_SW, 		0},	// SW (openssl)

/* available for the MSA4 instruction */
/* available for the RSA instruction */
 
};

/*
 * initializes the libica function list
 * Query s390_xxx_functions for each algorithm to check 
 * CPACF support and update the corresponding SHW-flags.
 */
int s390_initialize_functionlist() {

  unsigned int list_len = (sizeof(icaList)/sizeof(libica_func_list_element_int)), x;

  for (x=0; x<=list_len; x++) {
  	switch (icaList[x].type) {
	case KIMD:
		icaList[x].flags = icaList[x].flags | 
		((*s390_kimd_functions[icaList[x].id].enabled)? 4: 0);
  	break;
	case KMC:
		icaList[x].flags = icaList[x].flags | 
		((*s390_kmc_functions[icaList[x].id].enabled)? 4: 0);
		if (icaList[x].id == AES_128_ENCRYPT) { // check for the maximum size
                  if (*s390_kmc_functions[icaList[AES_256_ENCRYPT].id].enabled)
                        icaList[x].property = icaList[x].property | 4; // 256 bit
                  if (*s390_kmc_functions[icaList[AES_192_ENCRYPT].id].enabled)
			icaList[x].property = icaList[x].property | 2; // 192 bit
                  if (*s390_kmc_functions[icaList[AES_128_ENCRYPT].id].enabled) 
                        icaList[x].property = icaList[x].property | 1; // 128 bit
		}
  	break;
	case MSA4:
		icaList[x].flags = icaList[x].flags | 
		((*s390_msa4_functions[icaList[x].id].enabled)? 4: 0);
                  if (icaList[x].id == AES_128_ENCRYPT) { // check for the maximum size
                  	if (*s390_msa4_functions[icaList[AES_256_ENCRYPT].id].enabled)
                       	 	icaList[x].property = icaList[x].property | 4; // 256 bit
                  	if (*s390_msa4_functions[icaList[AES_192_ENCRYPT].id].enabled)
                        	icaList[x].property = icaList[x].property | 2; // 192 bit 
                  	if (*s390_msa4_functions[icaList[AES_128_ENCRYPT].id].enabled)
                        	icaList[x].property = icaList[x].property | 1; // 128 bit
                  }
                  else if (icaList[x].id == AES_128_XTS_ENCRYPT) { // check for the maximum size
                  	if      (*s390_msa4_functions[icaList[AES_256_XTS_ENCRYPT].id].enabled)
                        	icaList[x].property = icaList[x].property | 2; // 256 bit
                  	if (*s390_msa4_functions[icaList[AES_128_XTS_ENCRYPT].id].enabled)
                        	icaList[x].property = icaList[x].property | 1; // 128 bit
                }
  	break;
	default:
	break;
	}
  }
  return 0;
}

/**
 * Function that returns a list of crypto mechanisms supported by libica.
 * @param pmech_list
 *    Pointer to an array of libica_func_list_element
 *    If NULL, the API will return the number of elements to allocate
 *    in the @pmech_list_len parameter.
 *    If not NULL, libica will assume @pmech_list is an array that has
 *    @pmech_list_len elements.
 *    On success, @pmech_list will be filled out with the supported libica
 *    crypto mechanisms.
 * @param pmech_list_len
 *    number of list entries
 *    On input, pointer to the number of elements allocated in the 
 *    @pmech_list array.
 *    On output, @pmech_list_len will contain the number of items copied to
 *    the @pmech_list array, or the number of items libica would have returned
 *    in case the @pmech_list parameter is set to NULL.
 * 
 * @return
 *    0 on success
 *    EINVAL if at least one invalid parameter is given
 *
 *   A typical usage scenario would be that an exploiter makes a first call to
 *   ica_get_functionlist() with @pmech_list set to NULL in order to determine
 *   the number of elements to allocate. This is followed by a second call to
 *   ica_get_functionlist() with a valid pointer @pmech_list to an array of
 *   libica_func_list_element structures with @pmech_list_len elements.
 */
int s390_get_functionlist(libica_func_list_element *pmech_list, 
                                      unsigned int *pmech_list_len) {
  int x;
  
  if (!pmech_list_len) {
	return EINVAL;
  }

  if (!pmech_list) {
        *pmech_list_len = sizeof(icaList)/sizeof(libica_func_list_element_int);
	return 0;
  }
  else if (*pmech_list_len < 
          (sizeof(icaList)/sizeof(libica_func_list_element_int)) ) {
	return EINVAL;
  }
 
  for (x=0; x<*pmech_list_len; x++) {
      pmech_list[x].mech_mode_id = icaList[x].mech_mode_id;
      pmech_list[x].flags        = icaList[x].flags;
      pmech_list[x].property     = icaList[x].property;
  }
 
  return 0;
}

