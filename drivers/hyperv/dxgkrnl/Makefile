# SPDX-License-Identifier: GPL-2.0
# Makefile for the Linux video drivers.
# 5 Aug 1999, James Simmons, <mailto:jsimmons@users.sf.net>
# Rewritten to use lists instead of if-statements.

# Each configuration option enables a list of files.

# Uncomment to enable printing debug messages by default
#ccflags-y := -DDEBUG

obj-$(CONFIG_DXGKRNL)	+= dxgkrnl.o
dxgkrnl-y		:= dxgmodule.o hmgr.o misc.o dxgadapter.o ioctl.o dxgvmbus.o dxgprocess.o
