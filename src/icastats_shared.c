/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * Authors: Christian Maaser <cmaaser@de.ibm.com>
 *          Holger Dengler <hd@linux.vnet.ibm.com>
 *          Benedikt Klotz <benedikt.klotz@de.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2011, 2013
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <fcntl.h>
#include <dirent.h>
#include "icastats.h"
#include "init.h"

#define NOT_INITIALIZED (-1)
#define NAME_LENGHT 20

static stats_entry_t *stats = NULL;
volatile int stats_shm_handle = NOT_INITIALIZED;


static inline void atomic_add(int *x, int i)
{
	int old;
	int new;
	asm volatile ("	l	%0,%2\n"
		      "0:	lr	%1,%0\n"
		      "	ar	%1,%3\n"
		      "	cs	%0,%1,%2\n"
		      "	jl	0b"
		      :"=&d" (old), "=&d"(new), "=Q"(*x)
		      :"d"(i), "Q"(*x)
		      :"cc", "memory");
}


/* open shared memory segment
 * Arguments:
 * @user: if user is -1 stats_mmap will open the shared memory segent of the same
 * user.
 * If it is not -1, stats_mmap will treat it as uid and will open the shared memory
 * segment of this userid
 * return value:
 *  0 - Success
 * -1 - Error: See errno for errorcode
 */

int stats_mmap(int user)
{
	char shm_id[NAME_LENGHT];

	if (stats == NULL) {
		sprintf(shm_id, "icastats_%d",
			user == -1 ? geteuid() : (uid_t)user);

		stats_shm_handle = shm_open(shm_id, O_CREAT | O_RDWR,
						    S_IRUSR | S_IWUSR);

		if (stats_shm_handle == NOT_INITIALIZED)
			return -1;

		if (user > 0 && geteuid() == 0) {
			if (fchown(stats_shm_handle, user, user) == -1)
				return -1;
		}

		if (ftruncate(stats_shm_handle, STATS_SHM_SIZE) == -1)
			return -1;

		stats = (stats_entry_t *) mmap(NULL, STATS_SHM_SIZE, PROT_READ |
						 PROT_WRITE, MAP_SHARED,
						 stats_shm_handle, 0);
		if (stats == MAP_FAILED){
			close(stats_shm_handle);
			stats = NULL;
			return -1;
		}
	}
	return 0;
}

/* Close and/or delete the shared memory segment
 * Argument:
 * @unlink - if unlink is true the shared memory segment will be
 * deleted. If it is false it will only be closed.
 */

void stats_munmap(int unlink)
{
	char shm_id[NAME_LENGHT];
	sprintf(shm_id, "icastats_%d", geteuid());

	if (stats == NULL)
		return;

	munmap(stats, STATS_SHM_SIZE);
	close(stats_shm_handle);
	stats_shm_handle = NOT_INITIALIZED;

	if(unlink == SHM_DESTROY)
		shm_unlink(shm_id);
	stats = NULL;
}

/* query the shared memory segment for a specific field
 * arguments:
 * @field - the enum of the field see icastats.h
 * @hardware - valid values are ALGO_SW for software statistics
 * and ALGO_HW for hardware statistics
 * @direction - valid values are ENCRYPT and DECRYPT
 */

uint32_t stats_query(stats_fields_t field, int hardware, int direction)
{
	if (stats == NULL)
		return 0;

	if (direction == ENCRYPT)
		if (hardware == ALGO_HW)
			return stats[field].enc.hw;
		else
			return stats[field].enc.sw;
	else
		if (hardware == ALGO_HW)
			return stats[field].dec.hw;
		else
			return stats[field].dec.sw;
}

/* Returns the statistic data in a stats_entry_t array
 * @entries - Needs to be a array of size ICA_NUM_STATS.
 */

void get_stats_data(stats_entry_t *entries)
{
	unsigned int i;
	for(i = 0;i<ICA_NUM_STATS; i++){
		entries[i].enc.hw = stats_query(i, ALGO_HW, ENCRYPT);
		entries[i].enc.sw = stats_query(i, ALGO_SW, ENCRYPT);
		entries[i].dec.hw = stats_query(i, ALGO_HW, DECRYPT);
		entries[i].dec.sw = stats_query(i, ALGO_SW, DECRYPT);
	}
}



/* get the statistic data from all shared memory segments
 * accumulated in one variable
 * @sum: sum must be array of the size of ICA_NUM_STATS
 * After a call to this function sum contains the accumulated
 * data of all shared memory segments.
 * Return value:
 * 1 - Success
 * 0 - Error, check errno!
 */

int get_stats_sum(stats_entry_t *sum)
{
	unsigned int i;
	struct dirent *direntp;
	DIR *shmDir;

	memset(sum, 0, sizeof(stats_entry_t)*ICA_NUM_STATS);
	if((shmDir = opendir("/dev/shm")) == NULL)
		return 0;

	while((direntp = readdir(shmDir)) != NULL){
		if(strstr(direntp->d_name, "icastats_") != NULL){
			int fd;
			stats_entry_t *tmp;

			if((getpwuid(atoi(&direntp->d_name[9]))) == NULL){
				closedir(shmDir);
				return 0;
			}

			if ((fd = shm_open(direntp->d_name, O_RDONLY, 0)) == -1){
				closedir(shmDir);
				return 0;
			}
			if ((tmp = (stats_entry_t *)mmap(NULL, STATS_SHM_SIZE,
						    PROT_READ, MAP_SHARED,
						    fd, 0)) == MAP_FAILED){
				closedir(shmDir);
				close(fd);
				return 0;
			}

			for(i = 0; i<ICA_NUM_STATS; ++i){
				sum[i].enc.hw += tmp[i].enc.hw;
				sum[i].enc.sw += tmp[i].enc.sw;
				sum[i].dec.hw += tmp[i].dec.hw;
				sum[i].dec.sw += tmp[i].dec.sw;
			}
			munmap(tmp, STATS_SHM_SIZE);
			close(fd);
		}
	}
	closedir(shmDir);
	return 1;
}

/* Open the shared memory segment of the next user!
 * Each call to this function will open one file of the
 * /dev/shm directory. The function will return NULL when all files
 * in the directory were opened.
 * WARNING: You should never call this function only one time! Call this funtion in a loop with
 * abort condition unequal NULL.
 * The directory will reamin open if you don't wait for NULL!
 * Return value:
 * the name of the next user!
 * It is NULL when all files were opened.
 */

char *get_next_usr()
{
	struct dirent *direntp;
	static DIR *shmDir = NULL;

	/* Closes shm and set stats NULL */
	stats_munmap(SHM_CLOSE);

	if(shmDir == NULL){
		if((shmDir = opendir("/dev/shm")) == NULL)
			return NULL;
	}
	while((direntp = readdir(shmDir)) != NULL){
		if(strstr(direntp->d_name, "icastats_") != NULL){
			int uid = atoi(&direntp->d_name[9]);
			struct passwd *pwd;
			if((pwd = getpwuid(uid)) == NULL)
				return NULL;
			if(stats_mmap(uid) == -1)
				return NULL;

			return pwd->pw_name;
		} else{
			continue;
		}
	}
	closedir(shmDir);
	shmDir = NULL;
	return NULL;
}

#ifndef ICASTATS
/* increments a field of the shared memory segment
 * arguments:
 * @field - the enum of the field see icastats.h
 * @hardware - valid values are ALGO_SW for software statistics
 * and ALGO_HW for hardware statistics
 * @direction - valid values are ENCRYPT and DECRYPT
 */

void stats_increment(stats_fields_t field, int hardware, int direction)
{
	if (!ica_stats_enabled)
		return;

	if (stats == NULL)
		return;

	if(direction == ENCRYPT)
		if (hardware == ALGO_HW)
			atomic_add((int *)&stats[field].enc.hw, 1);
		else
			atomic_add((int *)&stats[field].enc.sw, 1);
	else
		if (hardware == ALGO_HW)
			atomic_add((int *)&stats[field].dec.hw, 1);
		else
			atomic_add((int *)&stats[field].dec.sw, 1);
}
#endif


/* Reset the shared memory segment to zero
 */
void stats_reset()
{
	if (stats == NULL)
		return;

	memset(stats, 0, sizeof(stats_entry_t)*ICA_NUM_STATS);
}


/* Delete all shared memory segments
 * Return values:
 * 1 - Success
 * 0 - Error, check errno!
 */

int delete_all()
{
	stats_munmap(SHM_DESTROY);
	struct dirent *direntp;
	DIR *shmDir;
	if((shmDir = opendir("/dev/shm")) == NULL)
		return 0;

	while((direntp = readdir(shmDir)) != NULL){
		if(strstr(direntp->d_name, "icastats_") != NULL){
			if(shm_unlink(direntp->d_name) == -1)
				return 0;
		}
	}
	closedir(shmDir);
	return 1;
}

