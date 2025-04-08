#!/bin/bash

if lszcrypt | grep -q -e "^[0-9a-f][0-9a-f]\.[0-9a-f][0-9a-f][0-9a-f][0-9a-f].*CEX.C.*online"; then
	ICAPATH=2 ./ecdh_test
else
	# Show output in log file for debugging
	lszcrypt
	exit 77
fi
