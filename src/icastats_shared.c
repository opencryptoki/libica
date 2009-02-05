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
#include <fcntl.h>
#include "include/icastats.h"

typedef struct statis_entry {
	uint32_t hardware;
	uint32_t software;
} stats_entry_t;

stats_entry_t *stats = 0;
int stats_refcounter = 0;

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
	if (!stats) {
		int stats_shm_handle = shm_open(STATS_SHM_ID, O_CREAT | O_RDWR,
						S_IRUSR | S_IWUSR | S_IRGRP |
						S_IWGRP | S_IROTH | S_IWOTH);
		if (stats_shm_handle == -1)
			return -1;
		if (ftruncate(stats_shm_handle, STATS_SHM_SIZE) == -1)
			return -1;
		stats = (stats_entry_t *) mmap(NULL, STATS_SHM_SIZE, PROT_READ |
					       PROT_WRITE, MAP_SHARED,
					       stats_shm_handle, 0);
		if (stats == MAP_FAILED) {
			stats = 0;
			return -1;
		}
	} else
		atomic_add(&stats_refcounter, 1);

	return 0;
}

void stats_munmap()
{
	if (--stats_refcounter == 0) {
		munmap(stats, STATS_SHM_SIZE);
		shm_unlink(STATS_SHM_ID);
		stats = 0;
	}
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

