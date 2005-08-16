#include <stdio.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <unistd.h>
#include "ica_api.h"

int
main(int argc, char *argv[])
{
	unsigned char output[1024*1024], *filename, dfname[] = "output";
	int rc = 0, bytes, total, bytes_to_do;
	FILE *fp;
	ICA_ADAPTER_HANDLE adapter_handle;

	switch (argc) {
		case 1:
			filename = dfname;
			bytes = 1024;
			break;
		case 2:
			filename = dfname;
			bytes = atoi(argv[1]);
			break;
		case 3:
			filename = argv[2];
			bytes = atoi(argv[1]);
			break;
		default:
			printf("Bad arguments\n");
			return 1;
	}

	fp = fopen(filename, "w");
	if (!fp) {
		printf("Unable to open \"%s\"\n", filename);
		return 2;
	}

	rc = icaOpenAdapter(0, &adapter_handle);
	if (rc != 0) {
		printf("icaOpenAdapter failed and returned %d (0x%x).\n", rc, rc);
	}

	total = 0;
	if (bytes == 0) {
		if ((rc = icaRandomNumberGenerate(adapter_handle, 0, output))) {
			printf("icaRandomNumberGenerate(0) returned %08X\n", rc);
#ifdef __s390__
			if (rc == ENODEV)
				printf("The usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
			return 1;
		}
	}
	while (bytes > 0) {
		bytes_to_do = (bytes > 1024*1024) ? 1024*1024 : bytes;
		if ((rc = icaRandomNumberGenerate(adapter_handle,
						   bytes_to_do, output))) {
			printf("icaRandomNumberGenerate(%d) returned %08X\n",
			       bytes_to_do, rc);
			return 1;
		}
		fwrite(output, 1, bytes_to_do, fp);
		bytes -= bytes_to_do;
		total += bytes_to_do;
		printf("Wrote %d pseudorandom bytes to \"%s\"\n", total, filename);
	}
	fclose(fp);
	
	return 0;
}

