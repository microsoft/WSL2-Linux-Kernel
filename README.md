= Introduction =

The WSL 2 Linux kernel repo provides the additional infrastructure necessary
to build and release the kernel component of WSL 2. It was never designed to
replace the current existing community and feedback channels for WSL,
especially through: https://github.com/microsoft/WSL. This is why we are not
accepting issues or pull requests through this repository.

If you have an issue relating to WSL, or the WSL 2 Linux kernel configuration,
please report it at the WSL GitHub: would like contribute to or report an issue
on the WSL2 kernel, please do so at the WSL GitHub:

https://github.com/microsoft/WSL/issues/new/choose

The WSL 2 Linux kernel is based on the Linux version from
https://www.kernel.org/. If you would like to contribute to or report an issue
on the Linux kernel in general, please do so on the upstream Linux GitHub:

https://www.kernel.org/doc/html/latest/process/submitting-patches.html

= Build Instructions =

1. Install a recent Ubuntu distribution
2. sudo apt install build-essential flex bison libssl-dev libelf-dev
3. make KCONFIG_CONFIG=Microsoft/config-wsl
