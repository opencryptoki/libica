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
 * Copyright IBM Corp. 2009-2019
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <getopt.h>
#include <pwd.h>
#include <libgen.h>
#include <errno.h>
#include <time.h>
#include <sys/utsname.h>
#include "icastats.h"

#define CMD_NAME "icastats"
#define COPYRIGHT "Copyright IBM Corp. 2009-2024"

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
	       " -r, --reset           set the own function counters to zero.\n"
	       " -R, --reset-all       reset the statistsics from all users. (root user only)\n"
	       " -d, --delete          delete your own statistics.\n"
	       " -D, --delete-all      delete the statistics from all users. (root user only)\n"
	       " -U, --user <username> show the statistics from one user. (root user only)\n"
	       " -S, --summary         show the accumulated statistics from all users. (root user only)\n"
	       " -A, --all             show the statistic tables from all users. (root user only)\n"
	       " -k, --key-sizes       show statistics per key size.\n"
	       " -j, --json            output the statistics in JSON format.\n"
	       " -v, --version         output version information\n"
	       " -h, --help            display help information\n");
}

#define getopt_string "rRdDU:SAkjvh"
static struct option getopt_long_options[] = {
	{"reset", 0, 0, 'r'},
	{"reset-all", 0, 0, 'R'},
	{"delete", 0, 0, 'd'},
	{"delete-all", 0, 0, 'D'},
	{"user", required_argument, 0, 'U'},
	{"summary", 0, 0, 'S'},
	{"all", 0, 0, 'A'},
	{"key-sizes", 0, 0, 'k'},
	{"json", 0, 0, 'j'},
	{"version", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};

const char *const STATS_DESC[ICA_NUM_STATS] = {
	STAT_STRINGS
};



#define CELL_SIZE 12
void print_stats(stats_entry_t *stats, int key_sizes)
{
	printf(" function       |             hardware         |              software\n");
	printf("----------------+------------------------------+-----------------------------\n");
	printf("                |        ENC    CRYPT     DEC  |        ENC     CRYPT    DEC \n");
	printf("----------------+------------------------------+-----------------------------\n");
	unsigned int i;
	for (i = 0; i < ICA_NUM_STATS; ++i) {
		if (!key_sizes && strncmp(STATS_DESC[i], "- ", 2) == 0)
			continue;

		if (i <= ICA_STATS_RSA_CRT_4096) {
			printf(" %14s |        %*lu          |         %*lu\n",
			       STATS_DESC[i],
			       CELL_SIZE,
			       stats[i].enc.hw,
			       CELL_SIZE,
			       stats[i].enc.sw);
		} else {
			printf(" %14s |%*lu     %*lu |%*lu    %*lu\n",
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

static int first_usr;

void print_json_header()
{
	char timestamp[200];
	struct utsname un;
	struct tm *tm;
	time_t t;

	time(&t);
	tm = gmtime(&t);
	/* ISO 8601 format: e.g. 2021-11-17T08:01:23Z (always UTC) */
	strftime(timestamp, sizeof(timestamp), "%FT%TZ", tm);

	if (uname(&un) != 0) {
		fprintf(stderr, "Failed to obtain system information, uname: %s",
		       strerror(errno));
		return;
	}

	printf("{\n\t\"host\": {\n");
	printf("\t\t\"nodename\": \"%s\",\n", un.nodename);
	printf("\t\t\"sysname\": \"%s\",\n", un.sysname);
	printf("\t\t\"release\": \"%s\",\n", un.release);
	printf("\t\t\"machine\": \"%s\",\n", un.machine);
	printf("\t\t\"date\": \"%s\"\n", timestamp);
	printf("\t},\n\t\"users\": [");

	first_usr = 1;
}

void print_stats_json(stats_entry_t *stats, const char *usr)
{
	unsigned int i;
	const char *last_func = NULL;

	if (!first_usr)
		printf(",");
	printf("\n\t\t{\n\t\t\t\"user\": \"%s\",\n", usr);
	printf("\t\t\t\"functions\": [");

	for (i = 0; i < ICA_NUM_STATS; ++i) {
		if (i < ICA_NUM_STATS - 1 &&
		    strncmp(STATS_DESC[i + 1], "- ", 2) == 0 &&
		    strncmp(STATS_DESC[i], "- ", 2) != 0) {
			last_func = STATS_DESC[i];
			continue;
		}

		if (i != 0)
			printf(",");
		printf("\n\t\t\t\t{\n");

		if (strncmp(STATS_DESC[i], "- ", 2) == 0 && last_func != NULL) {
			printf("\t\t\t\t\t\"function\": \"%s %s\",\n",
			       last_func, STATS_DESC[i]);
		} else {
			printf("\t\t\t\t\t\"function\": \"%s\",\n",
			       STATS_DESC[i]);
			last_func = NULL;
		}

		if (i <= ICA_STATS_RSA_CRT_4096) {
			printf("\t\t\t\t\t\"hw-crypt\": %lu,\n",
			       stats[i].enc.hw);
			printf("\t\t\t\t\t\"sw-crypt\": %lu\n",
			       stats[i].enc.sw);
		} else {
			printf("\t\t\t\t\t\"hw-enc\": %lu,\n",
			       stats[i].enc.hw);
			printf("\t\t\t\t\t\"sw-enc\": %lu,\n",
			       stats[i].enc.sw);
			printf("\t\t\t\t\t\"hw-dec\": %lu,\n",
			       stats[i].dec.hw);
			printf("\t\t\t\t\t\"sw-dec\": %lu\n",
			       stats[i].dec.sw);
		}

		printf("\t\t\t\t}");
	}

	printf("\n\t\t\t]\n\t\t}");

	first_usr = 0;
}

void print_json_footer()
{
	printf("\n\t]\n}\n");
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
	int key_sizes = 0;
	int json = 0;
	struct passwd *pswd;

	while ((rc = getopt_long(argc, argv, getopt_string,
				 getopt_long_options, &index)) != -1) {
		switch (rc) {
		case 'r':
			reset = 1;
			break;
		case 'R':
			if (geteuid() != 0) {
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
			if (geteuid() != 0) {
				fprintf(stderr,"You have no rights to delete all shared memory"
					" segments!\n");
				return EXIT_FAILURE;
			}
			delete = 2;
			break;
		case 'U':
			if ((pswd = getpwnam(optarg)) == NULL) {
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
		case 'k':
			key_sizes = 1;
			break;
		case 'j':
			json = 1;
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

	if (delete == 2) {
		if (delete_all() == -1) {
			perror("deleteall: ");
			return EXIT_FAILURE;
		}
		return EXIT_SUCCESS;
	} else if (delete) {
		stats_mmap(user);
		stats_munmap(user, SHM_DESTROY);
		return EXIT_SUCCESS;
	}
	if (all) {
		char *usr;
		stats_entry_t *entries;
		if (json)
			print_json_header();
		while ((usr = get_next_usr()) != NULL){
			if ((entries = malloc(sizeof(stats_entry_t)*ICA_NUM_STATS)) == NULL) {
				perror("malloc: ");
				return EXIT_FAILURE;
			}
			get_stats_data(NULL, entries);
			if (json) {
				print_stats_json(entries, usr);
			} else {
				printf("user: %s\n", usr);
				print_stats(entries, key_sizes);
			}
			free(entries);
		}
		if (json)
			print_json_footer();
		return EXIT_SUCCESS;
	}

	if (sum){
		stats_entry_t *entries;
		if ((entries = malloc(sizeof(stats_entry_t)*ICA_NUM_STATS)) == NULL) {
			perror("malloc: ");
			return EXIT_FAILURE;
		}

		if (!get_stats_sum(entries)) {
			perror("get_stats_sum: ");
			return EXIT_FAILURE;
		}
		if (json) {
			print_json_header();
			print_stats_json(entries, "all users");
			print_json_footer();
		} else {
			print_stats(entries, key_sizes);
		}
		return EXIT_SUCCESS;
	}

	if (reset == 2) {
		while (get_next_usr() != NULL)
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
	} else {
		stats_entry_t *stats;
		if ((stats = malloc(sizeof(stats_entry_t)*ICA_NUM_STATS)) == NULL) {
			perror("malloc: ");
			return EXIT_FAILURE;
		}
		get_stats_data(NULL, stats);
		if (json) {
			pswd = getpwuid(user == -1 ? geteuid() : (uid_t)user);
			if (pswd == NULL) {
				fprintf(stderr, "Failed to get user name");
				return EXIT_FAILURE;
			}
			print_json_header();
			print_stats_json(stats, pswd->pw_name);
			print_json_footer();
		} else {
			print_stats(stats, key_sizes);
		}
		free(stats);
	}
	return EXIT_SUCCESS;
}
