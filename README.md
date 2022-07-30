# Introduction

This fork of the [WSL2-Linux-Kernel](https://github.com/microsoft/WSL2-Linux-Kernel) is about enabling usb devices for use in [WSL2](https://docs.microsoft.com/en-us/windows/wsl/about#what-is-wsl-2) kernel.\
# Install Kali-linux

Install Kali-Linux WSL from CLI or Microsoft Store - skip if you already have it running\
`wsl --install --distribution kali-linux`

and complete the setup. After installing update the distro using:\
`sudo apt update && apt -y full-upgrade`

# Install USBIPD
Install the latest release of [usbipd](https://github.com/dorssel/usbipd-win/releases/latest) created by [Frans van Dorsselaer](https://github.com/dorsselaer), or use winget to install\
`winget install usbipd`

# Prepare dependencies and build environment
Switch to kali-linux in WSL\
Install the needed dependencies\
`sudo apt install usbipd git usbutils make libncurses-dev gcc bison flex dwarves libssl-dev libelf-dev python3 bc wireless-tools`

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

`sudo cp ~/git/WSL2-Linux-Kernel/arch/x86/boot/bzImage /mnt/c/Users/YOURUSER`. If you are no admin copy the file from \\WSL$\kali-linx to your user folder manually\
Create a file called .wslconfig inside /mnt/c/Users/YOURUSER and edit it as follow:
```
[wsl2]
kernel=C:\\Users\\YOUR_USERNAME\\bzImage
```
To enable the new kernel shutdown wsl `wsl --shutdown` and open kali-linux. The new kernel should be active.

# Firmware
Some drivers, like the RT2800 family, also need a firmware file. Since the WSL kernel is a single file and does cannot load the firmware file from /bin/firmware. So we need to load the firmware outside of the kernel.\

First you need to get the firmware file. For the RT2800 family you can install these by `sudo apt install firmware-misc-nonfree`.\
Copy the firmware file from '/lib/firmware' to `C:\Windows\System32\lxss\tools` and add\
`kernelCommandLine="firmware_class.path=/tools/firmware"` to the .wslconfig in  your userfolder `c:\Users\YOUR_USERNAME`\

```
[wsl2]
kernel=C:\\Users\\YOUR_USERNAME\\bzImage
kernelCommandLine="firmware_class.path=/tools/firmware"
```
Restart the kernel with `wss --shutdown`

# Load the driver/module
Go to your wireless driver, e.g. `cd /lib/modules/$(uname -r)/kernel/drivers/net/wireless/ralink/rt2x00`
use ls to show the content of the folder
```
┌──(user㉿PC)-[/lib/modules/5.10.102.1-microsoft-standard-WSL2+/kernel/drivers/net/wireless/ralink/rt2x00]
└─$ ls
rt2400pci.ko  rt2500usb.ko  rt2800mmio.ko  rt2800usb.ko  rt2x00mmio.ko  rt2x00usb.ko  rt73usb.ko
rt2500pci.ko  rt2800lib.ko  rt2800pci.ko   rt2x00lib.ko  rt2x00pci.ko   rt61pci.ko
```
Load your module using modprobe\
`sudo modprobe rt2800usb`

To check if the module has been loaded via 
`lsmod` 
```
└─$ lsmod
Module                  Size  Used by
rt2800usb              32768  0
rt2x00usb              28672  1 rt2800usb
rt2800lib             163840  1 rt2800usb
rt2x00lib              81920  3 rt2800usb,rt2x00usb,rt2800lib
mac80211             1249280  3 rt2x00lib,rt2x00usb,rt2800lib
cfg80211             1093632  2 rt2x00lib,mac80211
```
Now the module and firmware are loaded and ready for use!

# Attach the usb Wi-Fi adapter
Plugin the usb Wi-Fi adapter\
Switch to usbipd in windows to attach the usb device.\
Use `usbipd list` to show available devices
```
PS C:\Users\user> usbipd list
Connected:
BUSID  VID:PID    DEVICE                                                        STATE
6-2    046d:c539  USB Input Device                                              Not shared
6-4    148f:5572  802.11n USB Wireless LAN Card                                 Not shared
7-2    1b1c:1c05  USB Input Device                                              Not shared
```
The wifi adapter is located at busid 6-4

Share the adapter with the following command:\
`usbipd bind -b 6-4`
View the new settings
```
PS C:\Users\user> usbipd list
Connected:
BUSID  VID:PID    DEVICE                                                        STATE
6-2    046d:c539  USB Input Device                                              Not shared
6-4    148f:5572  802.11n USB Wireless LAN Card                                 Shared
7-2    1b1c:1c05  USB Input Device                                              Not shared
```
Finally attach the usb Wi-Fi adapter to your WSL instance
`usbipd wsl attach -b 6-4 -d kali-linux`
```
PS C:\Users\user> usbipd wsl list
BUSID  VID:PID    DEVICE                                                        STATE
6-2    046d:c539  USB Input Device                                              Not attached
6-4    148f:5572  802.11n USB Wireless LAN Card                                 Attached - kali-linux
7-2    1b1c:1c05  USB Input Device                                              Not attached
```
Switch back to Kali and run `lsusb`
```
┌──(user㉿PC)-[/mnt/c/Users/user]
└─$ lsusb
Bus 002 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 001 Device 002: ID 148f:5572 Ralink Technology, Corp. RT5572 Wireless Adapter
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
```
Finally the adapter is there!\

Run `iwonfig` to view the adapter settings
```
┌──(user㉿PC)-[/mnt/c/Users/user]
└─$ iwconfig
lo        no wireless extensions.

bond0     no wireless extensions.

dummy0    no wireless extensions.

tunl0     no wireless extensions.

sit0      no wireless extensions.

eth0      no wireless extensions.

wlan0     IEEE 802.11  ESSID:off/any
          Mode:Managed  Access Point: Not-Associated   Tx-Power=0 dBm
          Retry short  long limit:2   RTS thr:off   Fragment thr:off
          Power Management:off
```
Enable your Wi-Fi adapter with ifconfig\
`sudo ifconfig wlan0 up`

If no errors are shown your adapter is ready for use in WSL!


