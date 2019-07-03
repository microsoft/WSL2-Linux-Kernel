#! /bin/sh
set -x
docker run --rm -it -v $(pwd):/kernel-src -w /kernel-src simonferquel/kernel-builder:ubuntu-18.04 ./build-ms-kernel.sh