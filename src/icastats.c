/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Authors(s): Christian Maaser <cmaaser@de.ibm.com>
 *             Holger Dengler <hd@linux.vnet.ibm.com>
 *             Benedikt Klotz <benedikt.klotz@de.ibm.com>
 *             Ingo Tuchscherer <ingo.tuchscherer@de.ibm.com>
 *
 * Copyright IBM Corp. 2009, 2010, 2011, 2014
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <pwd.h>
#include <libgen.h>
#include "icastats.h"

#define CMD_NAME "icastats"
#define COPYRIGHT "Copyright IBM Corp. 2009, 2010, 2011, 2014."

void print_version(void)
{
	printf(CMD_NAME ": libica version " VERSION "\n" COPYRIGHT "\n");
}

void print_help(char *cmd)
{
	printf("Usage: %s [OPTION]\n\n", cmd);
	printf("This command is used to indicate whether libica uses hardware crypto functions or\n"
	       "software fallbacks. It provides an overview of the algorithms with modes of operation.\n"
	       "\n"
	       "Options:\n"
	       " -r, --reset         set the own function counters to zero.\n"
	       " -R, --reset-all     reset the statistsics from all users. (root user only)\n"
	       " -d, --delete        delete your own statistics.\n"
	       " -D, --delete-all    delete the statistics from all users. (root user only)\n"
	       " -U, --user <userid> show the statistics from one user. (root user only)\n"
	       " -S, --summary       show the accumulated statistics from alle users. (root user only)\n"
	       " -A, --all	     show the statistic tables from all users. (root user only)\n"
	       " -v, --version       output version information\n"
	       " -h, --help          display help information\n");
}

#define getopt_string "rRdDU:SAvh"
static struct option getopt_long_options[] = {
	{"reset", 0, 0, 'r'},
	{"reset-all", 0, 0, 'R'},
	{"delete", 0, 0, 'd'},
	{"delete-all", 0, 0, 'D'},
	{"user", required_argument, 0, 'U'},
	{"summary", 0, 0, 'S'},
	{"all", 0, 0, 'A'},
	{"version", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

const char *const STATS_DESC[ICA_NUM_STATS] = {
	STAT_STRINGS
};



#define CELL_SIZE 10
void print_stats(stats_entry_t *stats)
{
	printf(" function       |           hardware       |            software\n");
	printf("----------------+--------------------------+-------------------------\n");
	printf("                |      ENC    CRYPT   DEC  |      ENC    CRYPT   DEC \n");
	printf("----------------+--------------------------+-------------------------\n");
	unsigned int i;
	for (i = 0; i < ICA_NUM_STATS; ++i){
		if(i<=ICA_STATS_RSA_CRT){
			printf(" %14s |      %*d          |       %*d\n",
			       STATS_DESC[i],
			       CELL_SIZE,
			       stats[i].enc.hw,
			       CELL_SIZE,
			       stats[i].enc.sw);
		} else{
			printf(" %14s |%*d     %*d |%*d    %*d\n",
			       STATS_DESC[i],
			       CELL_SIZE,
			       stats[i].enc.hw,
			       CELL_SIZE,
			       stats[i].dec.hw,
			       CELL_SIZE,
			       stats[i].enc.sw,
			       CELL_SIZE,
			       stats[i].dec.sw);

	       }
	}
}




int main(int argc, char *argv[])
{
	int rc = 0;
	int index = 0;
	int reset = 0;
	int delete = 0;
	int sum = 0;
	int user = -1;
	int all = 0;
	struct passwd *pswd;

	while ((rc = getopt_long(argc, argv, getopt_string,
				 getopt_long_options, &index)) != -1) {
		switch (rc) {
		case 'r':
			reset = 1;
			break;
		case 'R':
			if(geteuid() != 0){
				fprintf(stderr,"You have no rights to reset all shared memory"
					" segments!\n");
				return EXIT_FAILURE;
			}
			reset = 2;
			break;
		case 'd':
			delete = 1;
			break;
		case 'D':
			if(geteuid() != 0){
				fprintf(stderr,"You have no rights to delete all shared memory"
					" segments!\n");
				return EXIT_FAILURE;
			}

			delete = 2;
			break;
		case 'U':
			if((pswd = getpwnam(optarg)) == NULL){
				fprintf(stderr, "The username %s is not known"
					" on this system.\n", optarg );
				return EXIT_FAILURE;
			}
			user = pswd->pw_uid;
			break;
		case 'S':
			sum = 1;
			break;
		case 'A':
			all = 1;
			break;
		case 'v':
			print_version();
			exit(0);
			break;
		case 'h':
			print_help(basename(argv[0]));
			exit(0);
		default:
			fprintf(stderr,
				"Try '%s --help' for more information.\n",
				basename(argv[0]));
			return EXIT_FAILURE;
		}
	}

	if (optind < argc) {
		fprintf(stderr, "%s: invalid option.\n\
			Try '%s --help' for more information.\n",
			argv[0], basename(argv[0]));
		return EXIT_FAILURE;
	}

	if(delete == 2){
		if(delete_all() == -1){
			perror("deleteall: ");
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	} else if(delete){
		stats_mmap(user);
		stats_munmap(SHM_DESTROY);
		return EXIT_SUCCESS;
	}
	if(all){
		char *usr;
		stats_entry_t *entries;
		while((usr = get_next_usr()) != NULL){
			if((entries = malloc(sizeof(stats_entry_t)*ICA_NUM_STATS)) == NULL){
				perror("malloc: ");
				return EXIT_FAILURE;
			}
			get_stats_data(entries);;
			printf("user: %s\n", usr);
			print_stats(entries);
			free(entries);
		}
		return EXIT_SUCCESS;
	}

	if (sum){
		stats_entry_t *entries;
		if((entries = malloc(sizeof(stats_entry_t)*ICA_NUM_STATS)) == NULL){
			perror("malloc: ");
			return EXIT_FAILURE;
		}

		if(!get_stats_sum(entries)){
			perror("get_stats_sum: ");
			return EXIT_FAILURE;
		}
		print_stats(entries);
		return EXIT_SUCCESS;


	}

	if(reset == 2){
		while(get_next_usr() != NULL)
			stats_reset();
		return EXIT_SUCCESS;

	}
	/* Need to open shm before it can be reseted */
	if (stats_mmap(user)) {
		fprintf(stderr, "Could not map shared memory region to local "
			"address space.\n");
		return EXIT_FAILURE;
	}

	if (reset) {
		stats_reset();
	} else{
		stats_entry_t *stats;
		if((stats = malloc(sizeof(stats_entry_t)*ICA_NUM_STATS)) == NULL){
			perror("malloc: ");
			return EXIT_FAILURE;
		}
		get_stats_data(stats);
		print_stats(stats);

	}
	return EXIT_SUCCESS;
}
