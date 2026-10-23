# Introduction

The [WSL2-Linux-Kernel][wsl2-kernel] repo contains the kernel source code and
configuration files for the [WSL2][about-wsl2] kernel.

# Reporting Bugs

If you discover an issue relating to WSL or the WSL2 kernel, please report it on
the [WSL GitHub project][wsl-issue]. It is not possible to report issues on the
[WSL2-Linux-Kernel][wsl2-kernel] project.

If you're able to determine that the bug is present in the upstream Linux
kernel, you may want to work directly with the upstream developers. Please note
that there are separate processes for reporting a [normal bug][normal-bug] and
a [security bug][security-bug].

# Feature Requests

Is there a missing feature that you'd like to see? Please request it on the
[WSL GitHub project][wsl-issue].

If you're able and interested in contributing kernel code for your feature
request, we encourage you to [submit the change upstream][submit-patch].

# Build Instructions

Instructions for building an x86_64 WSL2 kernel with an Ubuntu distribution using bash are
as follows:

1. Install the build dependencies:  
   `sudo apt install build-essential flex bison dwarves libssl-dev libelf-dev cpio qemu-utils rsync`

2. Modify WSL2 kernel configs (optional):  
   `make menuconfig KCONFIG_CONFIG=Microsoft/config-wsl`

3. Build the kernel using the WSL2 kernel configuration and put the modules in a `modules`
   folder under the current working directory:  
   `make KCONFIG_CONFIG=Microsoft/config-wsl && make INSTALL_MOD_PATH="$PWD/modules" modules_install`
   
   You may wish to include `-j$(nproc)` on the first `make` command to build in parallel.

4. Install the kernel's UAPI headers into a `headers` folder:  
   `make headers_install INSTALL_HDR_PATH="$PWD/headers"`

5. Build the `perf` tooling into a `perf` folder:  
   `make -C tools/perf NO_JEVENTS=1 NO_JVMTI=1 NO_LIBTRACEEVENT=1 install DESTDIR="$PWD/perf" prefix=/`

Then, you can use a provided script to create a VHDX containing the modules, headers, and perf
tooling:
   `./Microsoft/scripts/gen_artifacts_vhdx.sh "$PWD/modules" "$PWD/headers" "$PWD/perf" $(make -s kernelrelease) modules.vhdx`

To save space, you can now delete the compilation artifacts:
   `make clean && rm -r "$PWD/modules" "$PWD/headers" "$PWD/perf"`

If you prefer, you can also build the VHDX manually as follows. WSL expects the artifacts laid
out under `<kernelrelease>/{modules,linux-headers,perf}`, so first assemble a staging directory:

1. Stage the modules, headers, and perf tooling under the kernel release directory:
   ```
   release=$(make -s kernelrelease)
   mkdir -p "$PWD/staging/$release/linux-headers"
   cp -r "$PWD/modules/lib/modules/$release" "$PWD/staging/$release/modules"
   rm -f "$PWD/staging/$release/modules/build" "$PWD/staging/$release/modules/source"
   cp -r "$PWD/headers/." "$PWD/staging/$release/linux-headers"
   cp -r "$PWD/perf" "$PWD/staging/$release/perf"
   ```

2. Calculate the image size (plus 256MiB for slack):
   `image_size=$(du -bs "$PWD/staging" | awk '{print $1;}'); image_size=$((image_size + (256 * (1<<20))));`

3. Build a populated ext4 image:
   `mke2fs -L '' -d "$PWD/staging" -N $(( $(find "$PWD/staging" | wc -l) + 4096 )) -b 1024 -t ext4 "$PWD/modules.img" $((image_size / 1024))`

4. Convert the img to VHDX:
   `qemu-img convert -O vhdx "$PWD/modules.img" "$PWD/modules.vhdx"`

5. Clean up:
   `rm "$PWD/modules.img" # optionally the $PWD/staging, $PWD/modules, $PWD/headers, and $PWD/perf dirs too`

# Install Instructions

Please see the documentation on the [.wslconfig configuration
file][install-inst] for information on using a custom built kernel.

[wsl2-kernel]:  https://github.com/microsoft/WSL2-Linux-Kernel
[about-wsl2]:   https://docs.microsoft.com/en-us/windows/wsl/about#what-is-wsl-2
[wsl-issue]:    https://github.com/microsoft/WSL/issues/new/choose
[normal-bug]:   https://www.kernel.org/doc/html/latest/admin-guide/bug-hunting.html#reporting-the-bug
[security-bug]: https://www.kernel.org/doc/html/latest/admin-guide/security-bugs.html
[submit-patch]: https://www.kernel.org/doc/html/latest/process/submitting-patches.html
[install-inst]: https://docs.microsoft.com/en-us/windows/wsl/wsl-config#configure-global-options-with-wslconfig
