#!/bin/bash

if lszcrypt | grep -q -e "CEX.C.*online"; then
	ICAPATH=2 ./ecdh_test
else
	exit 77
fi
