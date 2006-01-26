/*
 * Oct 16, 2003
 * Kent Yoder <yoder1@us.ibm.com>
 *
 * ica-decrypt.c - DES-CBC decrypt a file using hardware
 *
 * compile:
 * $ gcc -o ica-decrypt -g -O0 ica-decrypt.c -lica
 * run:
 * $ ./ica-decrypt <infile> <outfile>
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <ica_api.h>

char *msg_digest;
void *dl_handle;
char *infile = NULL, *outfile = NULL; 
int infiledes = -1, outfiledes = -1;
struct stat file_stat;
int done = 0;

ICA_KEY_DES_SINGLE  key = {1,2,3,4,5,6,7,8};
ICA_DES_VECTOR      pIV = {1,2,3,4,5,6,7,8};

#define READ_SIZE			4096
#define SIZE_OF_THE_OUTPUT_BUFFER	READ_SIZE

void usage(char *argv0)
{
	int i;

	printf("usage: %s [-h] infile outfile\n", argv0);
	exit(-1);
}

int main(int argc, char **argv)
{
	int i, j, pAdapterHandle, written;
	int rc, bytes_read, outSize;
	char *buf, *outBuf;

	//memset( &key, 0x5a, sizeof(key));
	//memset( &pIV, 0x4b, sizeof(pIV));
	
	/* Parse the command line */
	for( i = 1; i < argc; i++ ) {
		if(strncmp(argv[i], "-h", 2) == 0) {
			usage(argv[0]);
		} else if (infile) {
			outfile = argv[i];
		} else {
			infile = argv[i];
		}
	}
	
	if( infile == NULL || outfile == NULL ) 
		usage(argv[0]);

	/* stat the file for size, etc */
	if( stat(infile, &file_stat) < 0 ) {
		perror("stat");
		return rc;
	}

	/* See if we can open the file */
	if( (infiledes = open(infile, O_RDONLY)) < 0 ) {
		perror("open");
		return rc;
	}
	if( (outfiledes = open(outfile, O_CREAT|O_WRONLY|O_TRUNC, S_IRWXU)) < 0 ) {
		perror("open");
		return rc;
	}

	if( (outBuf = (char *)malloc(SIZE_OF_THE_OUTPUT_BUFFER)) == NULL) {
		perror("malloc");
		goto file_close;
	}
	
	if( (buf = (char *)malloc(READ_SIZE)) == NULL) {
		perror("malloc");
		goto file_close;
	}
	
	rc = icaOpenAdapter( 0, &pAdapterHandle );

	if( rc ) {
		printf("icaOpenAdapter failed with rc: %d\n", rc);
		goto file_close;
	}

	outSize = SIZE_OF_THE_OUTPUT_BUFFER;

	
	bytes_read = read(infiledes, buf, READ_SIZE);

	if ( bytes_read < READ_SIZE ) {
		memset ( &buf[bytes_read], 0x0, READ_SIZE - bytes_read );
		done = 1;
	}

	rc = icaDesDecrypt( pAdapterHandle,
            MODE_DES_CBC,    /*unsigned int            mode,*/
            bytes_read,      /*unsigned int            dataLength,*/
            buf,             /*unsigned char          *pInputData,*/
            &pIV,            /*ICA_DES_VECTOR         *pIv,*/
            &key,            /*ICA_KEY_DES_TRIPLE     *pKeyDes,*/
            &outSize,        /*unsigned int           *pOutputDataLength,*/
            outBuf);    /*unsigned char          *pOutputData )*/


	written = write( outfiledes, outBuf, outSize);
	if (written != outSize) {
		printf("%d write failed, bailing out\n", __LINE__);
	}

	printf("%d passed icaDesDecrypt %d bytes\n", __LINE__, bytes_read);
	
	if(rc) {	
		perror("icaDesDecrypt");
		printf("%s %d icaDesDecrypt failed with rc: %d\n", __FILE__, __LINE__, rc);
		goto adapter_close;
	}

	if ( done )
		goto adapter_close;	

	memcpy(pIV, buf + bytes_read - sizeof(pIV), sizeof(pIV));
	bytes_read = read(infiledes, buf, READ_SIZE);
	while(bytes_read == READ_SIZE) {

	        rc = icaDesDecrypt( pAdapterHandle,
        	    MODE_DES_CBC,    /*unsigned int            mode,*/
	            bytes_read,      /*unsigned int            dataLength,*/
        	    buf,             /*unsigned char          *pInputData,*/
	            &pIV,            /*ICA_DES_VECTOR         *pIv,*/
        	    &key,            /*ICA_KEY_DES_TRIPLE     *pKeyDes,*/
	            &outSize,        /*unsigned int           *pOutputDataLength,*/
        	    outBuf);    /*unsigned char          *pOutputData )*/


		if(rc) {
			perror("icaDesDecrypt");	
			printf("%d icaDesDecrypt failed with rc: %d\n", __LINE__, rc);
			goto adapter_close;
		}
		
		printf("%d passed icaDesDecrypt %d bytes\n", __LINE__, bytes_read );

		written = write( outfiledes, outBuf, outSize);
		if (written != outSize) {
			printf("%d write failed, bailing out\n", __LINE__);
		}

		memcpy(pIV, buf + bytes_read - sizeof(pIV), sizeof(pIV));
		bytes_read = read(infiledes, buf, READ_SIZE);
	}

        if ( bytes_read < READ_SIZE && bytes_read != 0 ) {
                memset ( &buf[bytes_read], 0x0, READ_SIZE - bytes_read );

	/* Maybe we'll get  a 0 block here */
        rc = icaDesDecrypt( pAdapterHandle,
       	    MODE_DES_CBC,    /*unsigned int            mode,*/
            bytes_read,      /*unsigned int            dataLength,*/
       	    buf,             /*unsigned char          *pInputData,*/
            &pIV,            /*ICA_DES_VECTOR         *pIv,*/
       	    &key,            /*ICA_KEY_DES_TRIPLE     *pKeyDes,*/
            &outSize,        /*unsigned int           *pOutputDataLength,*/
       	    outBuf);    /*unsigned char          *pOutputData )*/

	if(rc) {
              perror("icaDesDecrypt");
              printf("%d icaDesDecrypt failed with rc: %d\n", __LINE__, rc);
              goto adapter_close;
        }

	printf("%d passed icaDesDecrypt %d bytes\n", __LINE__,bytes_read );
	written = write( outfiledes, outBuf, outSize);
	if (written != outSize) {
		printf("%d write failed, bailing out\n", __LINE__);
	}

        }


	
adapter_close:
	icaCloseAdapter(pAdapterHandle);
	
	
file_close:
	/* close the file */
	close(infiledes);
	close(outfiledes);
	
	return rc;
}

void oc_err_msg( char *str, int rc )
{
	printf("Error: %s returned:  %d ", str, rc );
	printf("\n\n");
}

