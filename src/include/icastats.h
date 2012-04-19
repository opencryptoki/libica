/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Christian Maaser <cmaaser@de.ibm.com>
 *
 * Copyright IBM Corp. 2009
 */

#ifndef __ICA_STATS_H__
#define __ICA_STATS_H__

#include <stdint.h>

typedef enum stats_fields {
	ICA_STATS_SHA1,
	ICA_STATS_SHA224,
	ICA_STATS_SHA256,
	ICA_STATS_SHA384,
	ICA_STATS_SHA512,
	ICA_STATS_RNG,
	ICA_STATS_RSA_MODEXPO,
	ICA_STATS_RSA_CRT,
	ICA_STATS_DES_ENCRYPT,
	ICA_STATS_DES_DECRYPT,
	ICA_STATS_3DES_ENCRYPT,
	ICA_STATS_3DES_DECRYPT,
	ICA_STATS_AES_ENCRYPT,
	ICA_STATS_AES_DECRYPT,
	ICA_STATS_CMAC_GENERATE,
	ICA_STATS_CMAC_VERIFY,
	ICA_STATS_CCM_ENCRYPT,
	ICA_STATS_CCM_DECRYPT,
	ICA_STATS_CCM_AUTH,
	ICA_STATS_GCM_ENCRYPT,
	ICA_STATS_GCM_DECRYPT,
	ICA_STATS_GCM_AUTH,

	ICA_NUM_STATS
} stats_fields_t;

#define STATS_SHM_ID "/libicai_stats"
#define STATS_SHM_SIZE (sizeof(stats_entry_t) * ICA_NUM_STATS + sizeof(int))

extern int stats_mmap();
extern void stats_munmap();
extern uint32_t stats_query(stats_fields_t field, int hardware);
extern void stats_increment(stats_fields_t field, int hardware);
extern void stats_reset();

#endif
