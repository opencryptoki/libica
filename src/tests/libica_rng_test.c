/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/* Copyright IBM Corp. 2010, 2011 */
#include <fcntl.h>
#include <sys/errno.h>
#include <stdio.h>
#include "ica_api.h"

unsigned char R[512];

extern int errno;

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

int main(int ac, char **av)
{
   int rc;
   ICA_ADAPTER_HANDLE adapter_handle;

   rc = icaOpenAdapter(0, &adapter_handle);
   if (rc != 0) {
      printf("icaOpenAdapter failed and returned %d (0x%x).\n", rc, rc);
   }

   rc = icaRandomNumberGenerate(adapter_handle, sizeof R, R);
   if (rc != 0) {
      printf("icaRandomNumberGenerate failed and returned %d (0x%x).\n", rc, rc);
#ifdef __s390__
      if (rc == ENODEV)
        printf("The usual cause of this on zSeries is that the CPACF instruction is not available.\n");
#endif
   }
   else {
      printf("\nHere it is:\n");
   }

   dump_array(R, sizeof R);

   if (!rc) {
      printf("\nWell, does it look random?\n\n");
   }

   icaCloseAdapter(adapter_handle);

   return 0;
}
