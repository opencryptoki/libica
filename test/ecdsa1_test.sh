#!/bin/sh

if lszcrypt | grep "CEX.C.*online" &> /dev/null; then
	ICAPATH=1 ./ecdsa_test
else
	exit 77
fi
