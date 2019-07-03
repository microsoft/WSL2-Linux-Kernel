#! /bin/sh
set -x
make -j $(nproc) KCONFIG_CONFIG=Microsoft/config-wsl