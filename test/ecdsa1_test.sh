#!/bin/bash

if lszcrypt | grep -q -e "CEX.C.*online"; then
	ICAPATH=1 ./ecdsa_test
else
	exit 77
fi
