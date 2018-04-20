#!/bin/sh

# Copyright 2013 6WIND S.A.

# Retry max 20 times to check fp-shared ready for mmap

retry_times=0
while [ $retry_times -lt 20 ]
do
	shared_name=`fp-shmem-ready fp-shared`
	if [ "$shared_name" == "fp-shared" ]; then
		break
	fi
	sleep 1
	let retry_times+=1
done
if [ "$shared_name" != "fp-shared" ]; then
	echo "Warning, fp-shared is not ready"
fi
