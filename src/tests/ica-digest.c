
/*
 * Dec 11, 2002
 * Kent Yoder <yoder1@us.ibm.com>
 *
 * compile:
 * $ gcc -o ica-digest -g -O0 ica-digest.c -lica
 * run:
 * $ ./ica-digest <file> | sha1sum -c
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
char *file = NULL;		/* the file to digest */
int filedes = -1;
struct stat file_stat;
void *file_map;

struct _chunk {
	void *data;
	unsigned int size;
} chunks[2];

#define SIZE_OF_THE_OUTPUT_BUFFER	LENGTH_SHA_HASH+5
#define READ_SIZE			192

void usage(char *argv0)
{
	int i;

	printf("usage: %s [-h] file\n", argv0);
	exit(-1);
}

int main(int argc, char **argv)
{
	int i, j, pAdapterHandle, first=1;
	int rc, bytes_read;
	SHA_CONTEXT icaShaContext;
	unsigned int md_len = SIZE_OF_THE_OUTPUT_BUFFER;

	memset(&icaShaContext, 0, LENGTH_SHA_CONTEXT);
	
	/* Parse the command line */
	for( i = 1; i < argc; i++ ) {
		if(strncmp(argv[i], "-h", 2) == 0) {
			usage(argv[0]);
		} else {
			file = argv[i];
		}
	}
	
	if( file == NULL ) 
		usage(argv[0]);

	/* stat the file for size, etc */
	if( stat(file, &file_stat) < 0 ) {
		perror("stat");
		return rc;
	}

	/* See if we can open the file */
	if( (filedes = open(file, O_RDONLY)) < 0 ) {
		perror("open");
		return rc;
	}

	if( (msg_digest = (char *)malloc(SIZE_OF_THE_OUTPUT_BUFFER)) == NULL) {
		perror("malloc");
		goto file_close;
	}
	
	if( (chunks[0].data = (void *)malloc(READ_SIZE)) == NULL) {
		perror("malloc 0");
		goto file_close;
	}
	
	if( (chunks[1].data = (void *)malloc(READ_SIZE)) == NULL) {
		perror("malloc 1");
		goto file_close;
	}
	chunks[0].size = chunks[1].size = 0;
	
	rc = icaOpenAdapter( 0, &pAdapterHandle );

	if( rc ) {
		printf("icaOpenAdapter failed with rc: %d\n", rc);
		goto file_close;
	}

	
	chunks[0].size = read(filedes, chunks[0].data, READ_SIZE);
	if (chunks[0].size < READ_SIZE) {
		rc = icaSha1(pAdapterHandle,
                        SHA_MSG_PART_ONLY,
                        chunks[0].size,
                        chunks[0].data,
                        LENGTH_SHA_CONTEXT,
                        &icaShaContext,
                        &md_len,
                        msg_digest);
	
		if(rc)	
			printf("%s %d icaSha1 failed on %s with rc: %d\n", __FILE__, __LINE__, argv[1], rc);
		goto adapter_close;	
	} else
		chunks[1].size = read(filedes, chunks[1].data, READ_SIZE);
	
	if (chunks[1].size < READ_SIZE) {
	
		rc = icaSha1(pAdapterHandle, 
			chunks[1].size ? SHA_MSG_PART_FIRST : SHA_MSG_PART_ONLY, 
			chunks[0].size,
			chunks[0].data, 
			LENGTH_SHA_CONTEXT, 
			&icaShaContext, 
			&md_len, 
			msg_digest);
	
		if(rc) {	
			printf("%s %d icaSha1 failed on %s with rc: %d\n", __FILE__, __LINE__, argv[1], rc);
			goto adapter_close;
		}

		if (chunks[1].size) {
			rc = icaSha1(pAdapterHandle, 
				SHA_MSG_PART_FINAL, 
				chunks[1].size,
				chunks[1].data, 
				LENGTH_SHA_CONTEXT, 
				&icaShaContext, 
				&md_len, 
				msg_digest);
		
			if(rc)	
				printf("%s %d icaSha1 failed on %s with rc: %d\n", __FILE__, __LINE__, argv[1], rc);
		}
		goto adapter_close;	
	}
	
	while(chunks[1].size == READ_SIZE) {
		rc = icaSha1(pAdapterHandle, 
			(first ? SHA_MSG_PART_FIRST : SHA_MSG_PART_MIDDLE), 
			chunks[0].size,
			chunks[0].data, 
			LENGTH_SHA_CONTEXT, 
			&icaShaContext, 
			&md_len, 
			msg_digest);

		if(rc) {
			printf("%d icaSha1 failed on %s with rc: %d\n", __LINE__, argv[1], rc);
			goto adapter_close;
		}
		
		first = 0;
		memcpy(chunks[0].data, chunks[1].data, chunks[1].size);

		chunks[1].size = read(filedes, chunks[1].data, READ_SIZE);
	}

 	rc = icaSha1(pAdapterHandle,
 		chunks[1].size ? SHA_MSG_PART_MIDDLE : SHA_MSG_PART_FINAL,
		chunks[0].size,
		chunks[0].data,
		LENGTH_SHA_CONTEXT,
		&icaShaContext,
		&md_len,
		msg_digest);

	if(rc) {
		printf("%d icaSha1 failed on %s with rc: %d\n", __LINE__, argv[1], rc);
		goto adapter_close;
	}

	if (chunks[1].size) {
	 	rc = icaSha1(pAdapterHandle,
 			SHA_MSG_PART_FINAL,
			chunks[1].size,
			chunks[1].data,
			LENGTH_SHA_CONTEXT,
			&icaShaContext,
			&md_len,
			msg_digest);

		if(rc) {
			printf("%d icaSha1 failed on %s with rc: %d\n", __LINE__, argv[1], rc);
			goto adapter_close;
		}
	}
	
adapter_close:
	icaCloseAdapter(pAdapterHandle);
	
	
	if(!rc) {	
		for( i = 0; i < LENGTH_SHA_HASH; i++ )
			printf("%02x", msg_digest[i]&0xff);
		printf("\t*%s\n", file);
	}


file_close:
	/* close the file */
	close(filedes);
	
	return rc;
}

void oc_err_msg( char *str, int rc )
{
	printf("Error: %s returned:  %d ", str, rc );
	printf("\n\n");
}

