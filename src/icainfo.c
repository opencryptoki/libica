/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/*
 * Display a list of all CP Assist for Cryptographic Function (CPACF)
 * operations supported by libica on a system.
 *
 * Author(s): Ralph Wuerthner <rwuerthn@de.ibm.com>
 * 	      Holger Dengler <hd@linux.vnet.ibm.com>
 * 	      Benedikt Klotz <benedikt.klotz@de.ibm.com>
 * 	      Ingo Tuchscherer <ingo.tuchscherer@de.ibm.com>
 *
 * Copyright IBM Corp. 2007, 2011, 2014
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <libgen.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include "s390_crypto.h"

#define CMD_NAME "icainfo"
#define COPYRIGHT "Copyright IBM Corp. 2007, 2014."

void print_version(void)
{
	printf(CMD_NAME ": libica version " VERSION "\n" COPYRIGHT "\n");
}

void print_help(char *cmd)
{
	printf("Usage: %s [OPTION]\n", cmd);
	printf
	    ("Display a list of all CP Assist for Cryptographic Function "
	     "(CPACF)\noperations supported by libica on this system.\n"
	     "\n" "Options:\n"
	     " -v, --version  show version information\n"
	     " -h, --help     display this help text\n");
}

#define getopt_string "qvh"
static struct option getopt_long_options[] = {
	{"version", 0, 0, 'v'},
	{"help", 0, 0, 'h'},
	{0, 0, 0, 0}
};


struct crypt_pair {
	char *name;
	int algo_id;
};

static struct crypt_pair crypt_map[] = {
	{"SHA-1", SHA1},
        {"SHA-224", SHA224},
        {"SHA-256", SHA256},
        {"SHA-384", SHA384},
        {"SHA-512", SHA512},
        {"P_RNG", P_RNG},
        {"RSA ME", RSA_ME},
        {"RSA CRT", RSA_CRT},
        {"DES ECB", DES_ECB},
        {"DES CBC", DES_CBC},
        {"DES CBC CS", DES_CBC_CS},
        {"DES OFB", DES_OFB},
        {"DES CFB", DES_CFB},
        {"DES CTR", DES_CTR},
        {"DES CTRLST", DES_CTRLST},
        {"DES CBC MAC", DES_CBC_MAC},
        {"DES CMAC", DES_CMAC},
        {"3DES ECB", DES3_ECB},
        {"3DES CBC", DES3_CBC},
        {"3DES CBC CS", DES3_CBC_CS},
        {"3DES OFB", DES3_OFB},
        {"3DES CFB", DES3_OFB},
        {"3DES CTR", DES3_CTR},
        {"3DES CTRLIST", DES3_CTRLST},
        {"3DES CBC MAC", DES3_CBC_MAC},
        {"3DES CMAC", DES3_CMAC},
        {"AES ECB", AES_ECB},
        {"AES CBC", AES_CBC},
        {"AES CBC CS", AES_CBC_CS},
        {"AES OFB", AES_OFB},
        {"AES CFB", AES_CFB},
        {"AES CTR", AES_CTR},
        {"AES CTRLST", AES_CTRLST},
        {"AES CBC MAC", AES_CBC_MAC},
        {"AES CMAC", AES_CMAC},
        {"AES CCM", AES_CCM},
        {"AES GCM", AES_GCM},
        {"AES XTS", AES_XTS},
	{NULL,0}
};


int is_crypto_card_loaded()
{
	DIR* sysDir;
	FILE *file;
	char dev[PATH_MAX] = "/sys/devices/ap/";
	struct dirent *direntp;
	char *type = NULL;
	size_t size;
	char c;

	if ((sysDir = opendir(dev)) == NULL )
		return 0;

	while((direntp = readdir(sysDir)) != NULL){
		if(strstr(direntp->d_name, "card") != 0){
			snprintf(dev, PATH_MAX, "/sys/devices/ap/%s/type",
			 	 direntp->d_name); 

			if ((file = fopen(dev, "r")) == NULL){
	                        closedir(sysDir);
                                return 0;
			}
		
			if (getline(&type, &size, file) == -1){
				fclose(file);
				closedir(sysDir);
				return 0;
			}
					
 			/* ignore \n
			 * looking for CEX??A and CEX??C
			 * Skip type CEX??P cards
 			 */
			if (type[strlen(type)-2] == 'P'){
				free(type);
				type = NULL;
			        fclose(file);
                        	continue;
			}
			free(type);
			type = NULL;
			fclose(file);

			snprintf(dev, PATH_MAX, "/sys/devices/ap/%s/online",
				direntp->d_name);
			if ((file = fopen(dev, "r")) == NULL){
				closedir(sysDir);
				return 0;
			}
			if((c = fgetc(file)) == '1'){
				fclose(file);
				return 1;
			}
			fclose(file);
		}
	}
	closedir(sysDir);
	return 0;
}	
	


int main(int argc, char **argv)
{
	int rc;
	int index = 0;

    unsigned int mech_len;
    libica_func_list_element *pmech_list = NULL;
	int flag;	

	while ((rc = getopt_long(argc, argv, getopt_string,
				 getopt_long_options, &index)) != -1) {
		switch (rc) {
		case 'v':
			print_version();
			exit(0);
			break;
		case 'h':
			print_help(basename(argv[0]));
			exit(0);
		default:
			fprintf(stderr, "Try '%s --help' for more"
				" information.\n", basename(argv[0]));
			exit(1);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "%s: invalid option.\n"
			"Try '%s --help' for more information.\n",
			argv[0], basename(argv[0]));
		exit(1);
	}

	printf("The following CP Assist for Cryptographic Function (CPACF) \n"
	       "operations are supported by libica on this system:\n");

	if (ica_get_functionlist(NULL, &mech_len) != 0){
		perror("get_functionlist: ");
		return EXIT_FAILURE;
	}
	pmech_list = malloc(sizeof(libica_func_list_element)*mech_len);
	if (ica_get_functionlist(pmech_list, &mech_len) != 0){
		perror("get_functionlist: ");
		free(pmech_list);
		return EXIT_FAILURE;
	}

	flag = is_crypto_card_loaded();

	#define CELL_SIZE 3

	int i, j;
	printf(" function      | # hardware | #software\n");
	printf("---------------+------------+--------------\n");
	for(i = 0;crypt_map[i].algo_id;i++){
		for(j=0;j<mech_len;j++){
			if(crypt_map[i].algo_id == pmech_list[j].mech_mode_id){
				if(flag){
					printf("%14s |    %*s     |     %*s\n", 
						crypt_map[i].name,
						CELL_SIZE,
						pmech_list[j].flags &
						(ICA_FLAG_SHW | ICA_FLAG_DHW)
						? "yes" : "no",		
						CELL_SIZE,	
						pmech_list[j].flags & ICA_FLAG_SW
						? "yes" : "no");
				} else{
                                        printf("%14s |    %*s     |     %*s\n",
                                                crypt_map[i].name,
						CELL_SIZE,
                                                (pmech_list[j].flags &
                                                ICA_FLAG_SHW)
                                                ? "yes" : "no",
						CELL_SIZE,
                                                pmech_list[j].flags & ICA_FLAG_SW
                                                ? "yes" : "no");
	
				}
				break;		
			}

		}
	}
	free(pmech_list);
	return EXIT_SUCCESS;
}
