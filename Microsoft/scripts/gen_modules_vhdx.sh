#!/bin/bash
set -ueo pipefail

if [ $# -ne 2 ] || [ ! -d "$1" ]; then
	printf '%s' "Usage ./$0 <modules dir> <output file>" 1>&2
	exit 1
fi

if [ -e "$2" ]; then
	printf '%s' "Refusing to overwrite existing file $2" 1>&2
	exit 2
fi


# Calculate modules size (+ 256MiB for slack)
modules_size=$(du -bs "$1" | awk '{print $1;}')
modules_size=$((modules_size + (256*(1<<20))))

# Create our scratch directory
tmp_dir=$(mktemp -d)

# Create a blank image file of the right size
dd if=/dev/zero of="$tmp_dir/modules.img" bs=1024 count=$((modules_size / 1024))

# Set up fs and mount
lo_dev=$(losetup --find --show "$tmp_dir/modules.img")
mkfs -t ext4 "$lo_dev"
mkdir "$tmp_dir/modules_img"
mount "$lo_dev" "$tmp_dir/modules_img"
chmod a+rw "$tmp_dir/modules_img"

# Copy over the contents of $1
cp -r "$1"/* "$tmp_dir/modules_img"
umount "$tmp_dir/modules_img"

# Do the final conversion
qemu-img convert -O vhdx "$tmp_dir/modules.img" "$2"

# Fix ownership since we're probably running under sudo
if [ -n "$SUDO_USER" ]; then
	chown "$SUDO_USER:$SUDO_USER" "$2"
fi

