/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2001, 2015 */

#include <fcntl.h>
#include <memory.h>
#include <sys/errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "ica_api.h"
#include <sys/time.h>
#include "libica_rsa_test.h"

extern int errno;

static int handle_ica_error(int rc, char *message)
{
        printf("Error in %s: ", message);
        switch (rc) {
                case 0:
                  printf("OK\n");
                  break;
                case EINVAL:
                  printf("Incorrect parameter.\n");
                  break;
                case EPERM:
                  printf("Operation not permitted by Hardware.\n");
                  break;
                case EIO:
                  printf("I/O error.\n");
                  break;
                default:
                  perror("");
        }
        return rc;
}

void dump_array(unsigned char *ptr, unsigned int size)
{
   unsigned char *ptr_end;
   unsigned char *h;
   int i = 1;

   h = ptr;
   ptr_end = ptr + size;
   while (h < (unsigned char *)ptr_end) {
      printf("0x%02x ",(unsigned char ) *h);
      h++;
      if (i == 8) {
         printf("\n");
         i = 1;
      } else {
         ++i;
      }
   }
   printf("\n");
}

int main(int argc, char **argv)
{
	ica_adapter_handle_t	adapter_handle;
	unsigned char*	my_result;
	unsigned char*	my_result2;
	int				i, rc;
	unsigned int silent = 0;
	struct timeval start,end;

	if (argc > 1) {
		if (strstr(argv[1], "silent"))
			silent = 1;
	}

   rc = ica_open_adapter(&adapter_handle);
   if (rc != 0) {
      printf("ica_open_adapter failed and returned %d (0x%x).\n", rc, rc);
   }

	/* Iterate over key sizes (1024, 2048 and 4096) */
	for (i = 0; i < 6; i++) {

	    /* encrypt with public key (ME) */
		if (!silent) {
		    printf("modulus size = %d\n", RSA_BYTE_LENGHT[i]);
		}

		my_result =  malloc(RESULT_LENGTH);
		bzero(my_result, RESULT_LENGTH);

		my_result2 = malloc(RESULT_LENGTH);
		bzero(my_result2, RESULT_LENGTH);

		ica_rsa_key_mod_expo_t mod_expo_key = {RSA_BYTE_LENGHT[i], n[i], e[i]};

		rc = ica_rsa_mod_expo(adapter_handle, input_data,
							  &mod_expo_key, my_result);
		if (rc)
			exit(handle_ica_error(rc, "ica_rsa_key_mod_expo"));

		if (!silent) {
			printf("\n\n\n\n\n result of encrypt with public key\n");
			dump_array((unsigned char *)my_result, RSA_BYTE_LENGHT[i]);
			printf("Ciphertext \n");
			dump_array(ciphertext[i],RSA_BYTE_LENGHT[i]);
		}
		if (memcmp(my_result,ciphertext[i],RSA_BYTE_LENGHT[i])){
			printf("Ciphertext mismatch\n");
			return -1;
		}

		/* decrypt with private key (CRT) */
		ica_rsa_key_crt_t crt_key = {RSA_BYTE_LENGHT[i], p[i], q[i], dp[i],
									 dq[i], qinv[i]};

		gettimeofday(&start, NULL);

		rc = ica_rsa_crt(adapter_handle, ciphertext[i], &crt_key, my_result2);
		if(rc)
			exit(handle_ica_error(rc, "ica_rsa_crt"));

		gettimeofday(&end, NULL);
		if (!silent) {
			printf("RSA decrypt with key[%d] (l=%d) took %06lu µs.\n", i,
				RSA_BYTE_LENGHT[i], (end.tv_sec*1000000+end.tv_usec)-
									(start.tv_sec*1000000+start.tv_usec));

			printf("Result of decrypt\n");
			dump_array((unsigned char *)my_result2, sizeof(input_data));
			printf("original data\n");
			dump_array(input_data, sizeof(input_data));
		}
		if (memcmp(input_data,my_result2,sizeof(input_data)) != 0) {
			printf("Results do not match.  Failure!\n");
			return -1;
		}

	} // end loop

   rc = ica_open_adapter(&adapter_handle);
   if (rc != 0) {
      printf("ica_close_adapter failed and returned %d (0x%x).\n", rc, rc);
   }
	printf("All RSA testcases finished successfully\n");
   return 0;
}

