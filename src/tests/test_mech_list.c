/* This program is released under the Common Public License V1.0
 *
 * You should have received a copy of Common Public License V1.0 along with
 * with this program.
 */

/**
 * This is something like what you can expect openCryptoki to do when
 * it requests a mechanism list from your library.
 *
 * Copyright IBM Corp. 2005, 2009
 */

#include <stdio.h>
#include <stdlib.h>
#include "mech_types.h"
#include "ica_api.h"

int
main(void)
{
	struct mech_list_item head;
	struct mech_list_item *item, *next;
	generate_pkcs11_mech_list(&head);
	item = head.next;
	while (item) {
		next = item->next;
		printf("Mechanism type: [%8lX]\n", item->element.mech_type);
		free(item);
		item = next;
	}
	return 0;
}

