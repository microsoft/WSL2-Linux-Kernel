#!/bin/bash
set -ueo pipefail

if [ $# -ne 5 ] || [ ! -d "$1" ] || [ ! -d "$2" ] || [ ! -d "$3" ]; then
	printf '%s\n' "Usage ./$0 <modules dir> <headers dir> <perf dir> <kernelversion> <output file>" 1>&2
	exit 1
fi

modules_dir="$1"
headers_dir="$2"
perf_dir="$3"
kernel_version="$4"
output_file="$5"

if [ -e "$output_file" ]; then
	printf '%s\n' "Refusing to overwrite existing file $output_file" 1>&2
	exit 2
fi

if [ ! -d "$modules_dir/lib/modules/$kernel_version" ]; then
	printf '%s\n' "No modules found at $modules_dir/lib/modules/$kernel_version" 1>&2
	exit 3
fi

# Create our scratch directory
tmp_dir=$(mktemp -d)
trap 'rm -rf "$tmp_dir"' EXIT

# WSL expects the artifacts laid out under <kernelversion>/{modules,linux-headers,perf}:
#   <kernelversion>/modules            - the modules tree (modules.dep, kernel/, ...)
#   <kernelversion>/linux-headers      - the installed UAPI headers (contains include/)
#   <kernelversion>/perf               - the perf tooling (contains bin/perf)
staging_dir="$tmp_dir/staging"
artifacts_dir="$staging_dir/$kernel_version"
mkdir -p "$artifacts_dir"

# Copy over the modules tree
cp -r "$modules_dir/lib/modules/$kernel_version" "$artifacts_dir/modules"

# The build/source symlinks point at the build-time kernel tree, which doesn't
# exist inside WSL. Drop them; WSL recreates the build symlink pointing at the
# bundled headers.
rm -f "$artifacts_dir/modules/build" "$artifacts_dir/modules/source"

# Copy over the installed UAPI headers (headers_dir contains include/)
mkdir -p "$artifacts_dir/linux-headers"
cp -r "$headers_dir/." "$artifacts_dir/linux-headers"

# Copy over the perf tooling (perf_dir contains bin/perf)
mkdir -p "$artifacts_dir/perf"
cp -r "$perf_dir/." "$artifacts_dir/perf"

# Calculate the image size (staging size + 256MiB for slack)
staging_size=$(du -bs "$staging_dir" | awk '{print $1;}')
image_size=$((staging_size + (256 * (1 << 20))))
image_blocks=$((image_size / 1024))

# Reserve one inode per file plus slack so the many small header files fit
inode_count=$(find "$staging_dir" | wc -l)
inode_count=$((inode_count + 4096))

mke2fs -q -L '' -d "$staging_dir" -N "$inode_count" -b 1024 -t ext4 "$tmp_dir/modules.img" "$image_blocks"

# Do the final conversion
qemu-img convert -O vhdx "$tmp_dir/modules.img" "$output_file"
