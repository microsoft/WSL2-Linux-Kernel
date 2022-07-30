# Introduction

This fork of the [WSL2-Linux-Kernel](https://github.com/microsoft/WSL2-Linux-Kernel) is about enabling usb devices for use in [WSL2](https://docs.microsoft.com/en-us/windows/wsl/about#what-is-wsl-2) kernel.\
# Install ali-linux

Install Kali-Linux WSL from CLI or Microsoft Store - skip if you already have it running\
`wsl --install --distribution kali-linux`

and complete the setup. After installing update the distro using:\
`sudo apt update && apt -y full-upgrade`

# Install USBIPD
Install [usbipd](https://github.com/dorssel/usbipd-win/releases/latest) created by [Frans van Dorsselaer](https://github.com/dorsselaer), or use winget to install\
`winget install usbipd`

Switch to the kali-lnux distro and install usbip\
`sudo apt install usbip`

# Prepare kernel

Install the needed dependencies\
`sudo apt install git usbutils make libncurses-dev gcc bison flex dwarves libssl-dev libelf-dev python3 bc`

Clone the Kernel into your WSL, create folder git into your home dir\
`mkdir ~/git`

Clone the WSL Kernel using\
If your driver is already part of the distro (like the RT2800 family driver) you still need to create a build. 
`git clone https://github.com/marco73/WSL2-Linux-Kernel.git`

# Add your the drivers to the build
If your usb device needs a driver put your driver inside `drivers/net/wireless/` with the manufacturer name like "ralink", "realtek", etc. For example `drivers/net/wireless/realtek`\

Add the location of your driver to `drivers/net/wireless/realtek/Kconfig`, `source "drivers/net/wireless/realtek/rtl88x2bu/Kconfig"`\
Edit the Makefile `drivers/net/wireless/realtek/Makefile` to include the driver location by adding the line `obj-$(CONFIG_RTL8822BU) += rtl88x2bu/`

# Prepare build
Go into the root of the WSL kernel and open menuconfig\
`make -j $(expr $(nproc) - 1) KCONFIG_CONFIG=Microsoft/config-wsl menuconfig`

In menu config go to\
`Device Drivers` ->Select\
`Network device support` -> press [space] -> Select\
`Wireless LAN` -> Enable your device(s) here\
Select [Save] and save to `Microsoft/config-wsl`
Select [Exit] until menuconfig is closed.

# Build the WSL kernel

Load modules `sudo make -j $(expr $(nproc) - 1) KCONFIG_CONFIG=Microsoft/config-wsl modules`\
modules install `sudo make -j $(expr $(nproc) - 1) KCONFIG_CONFIG=Microsoft/config-wsl modules_install`\
Build the kernel `sudo make -j $(expr $(nproc) - 1) KCONFIG_CONFIG=Microsoft/config-wsl`\

# Enable the new kernel

This produces a compresses kernel called bzImage. copy this file from ~/src/WSL2-Linux-Kernel/arch/x86/boot to /mnt/Users/YOUR_USERNAME\
Note: Replace YOURUSER with your actual user

`cp ~/src/WSL2-Linux-Kernel/arch/x86/boot/bzImage /mnt/c/Users/YOURUSER`. If you are no admin copy the file from \\WSL$\kali-linx to your user folder manually\
Create a file called .wslconfig inside /mnt/c/Users/YOURUSER and edit it as follow:
```
[wsl2]
kernel=C:\\Users\\YOUR_USERNAME\\bzImage
```
To enable the new kernel shutdown wsl `wsl --shutdown` and open kali-linux. The new kernel should be active.




