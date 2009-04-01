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

#include <unistd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include "include/icastats.h"

typedef struct statis_entry {
	uint32_t hardware;
	uint32_t software;
} stats_entry_t;

stats_entry_t *stats = 0;
int *stats_ref_counter = 0;
int stats_shm_handle = 0;

void atomic_add(int *x, int i)
{
	int old;
	int new;
	asm volatile ("	l	%0,%2\n"
		      "LOOP:	lr	%1,%0\n"
		      "	ar	%1,%3\n"
		      "	cs	%0,%1,%2\n"
		      "	jl	LOOP":"=&d" (old), "=&d"(new), "=Q"(*x)
		      :"d"(i), "Q"(*x)
		      :"cc", "memory");
}

int stats_mmap()
{
	/* Use flock to avoid races between open and close of shm by different
	 * processes. Put reference counter into shm to check how much
	 * processes are accesing the shm. Additionaly a global and a local
	 * handle for the shm are used to prevend different threads from
	 * overriding their shm handle one another.
	 */
	if (!stats) {
		int local_stats_shm_handle = shm_open(STATS_SHM_ID, O_CREAT | O_RDWR,
		                            S_IRUSR | S_IWUSR | S_IRGRP |
		                            S_IWGRP | S_IROTH | S_IWOTH);
		if (local_stats_shm_handle == -1)
			return -1;
		if (ftruncate(local_stats_shm_handle, STATS_SHM_SIZE) == -1)
			return -1;

		if (flock(local_stats_shm_handle, LOCK_EX) == -1)
			return -1;
		if (stats_shm_handle != 0) {
			flock(local_stats_shm_handle, LOCK_UN);
			return 0;
		}
		stats_ref_counter = (int *) mmap(NULL, STATS_SHM_SIZE, PROT_READ |
					         PROT_WRITE, MAP_SHARED,
					         local_stats_shm_handle, 0);
		if (stats_ref_counter == MAP_FAILED) {
			stats_ref_counter = 0;
			flock(local_stats_shm_handle, LOCK_UN);
			return -1;
		}
		++(*stats_ref_counter);
		stats = (stats_entry_t *) (stats_ref_counter + 1);
		stats_shm_handle = local_stats_shm_handle;
		flock(local_stats_shm_handle, LOCK_UN);
	} else {
		if (flock(stats_shm_handle, LOCK_EX) == -1)
			return -1;
		++(*stats_ref_counter);
		flock(stats_shm_handle, LOCK_UN);
	}

	return 0;
}

void stats_munmap()
{
	if (!stats)
		return;

	if (flock(stats_shm_handle, LOCK_EX) == -1)
		return -1;
	if (--(*stats_ref_counter) == 0) {
		munmap(stats_ref_counter, STATS_SHM_SIZE);
		shm_unlink(STATS_SHM_ID);
		stats = 0;
	}
	else
		flock(stats_shm_handle, LOCK_UN);
}

uint32_t stats_query(stats_fields_t field, int hardware)
{
	if (!stats)
		return 0;

	if (hardware)
		return stats[field].hardware;
	else
		return stats[field].software;
}

void stats_increment(stats_fields_t field, int hardware)
{
	if (!stats)
		return;

	if (hardware)
		atomic_add((int *)&stats[field].hardware, 1);
	else
		atomic_add((int *)&stats[field].software, 1);
}

void stats_reset()
{
	unsigned int i;
	for (i = 0; i != ICA_NUM_STATS; ++i) {
		stats[i].hardware = 0;
		stats[i].software = 0;
	}
}

