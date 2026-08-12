# is_vm
Determine whether the application appears to be running inside a virtual machine or analysis (sandbox) environment.

`bool is_vm();`

## Returns:
bool: true if a virtualized or sandboxed environment is detected, false otherwise.

## Remarks:
This function targets **VMware and VirtualBox guests specifically**, plus Windows Sandbox. It runs several independent checks and returns true if any one of them matches, so a single positive result is enough to report a virtual machine. Each check probes a different channel, which means hiding one of them still leaves the others: the CPU's hypervisor vendor signature, the VMware backdoor I/O port, the firmware tables (SMBIOS/DMI, and VirtualBox's ACPI tables on Windows), device nodes whose driver can only bind to emulated hardware, the emulated display adapter's PCI vendor id, the Windows Sandbox profile marker, and finally the system model, BIOS, baseboard, disk and video strings reported by the operating system.

Two categories of signal are deliberately **not** used, and knowing why explains what this function will and will not tell you.

Generic virtualization is not reported. Hyper-V, WSL2, KVM, Xen and QEMU do not make this function return true, and neither does Windows Virtualization Based Security (VBS/HVCI/Credential Guard). A physical Windows 11 machine with VBS or Hyper-V enabled sets the CPU's hypervisor-present bit and identifies its hypervisor as "Microsoft Hv" while not being a virtual machine at all, so treating those signals as proof would misclassify a large number of ordinary players. Windows Sandbox is the one exception: although it is Hyper-V backed, it leaves a specific profile marker that never appears on a normal desktop. If you need to detect virtualization in general rather than these particular products, this function is not the right tool.

Installed software is not inspected. Guest-tool directories and files, running guest daemons such as vmtoolsd or VBoxService, network adapter MAC address prefixes, and product installation records in the registry are all ignored, because they answer "is virtualization software installed on this machine?" rather than "is this process executing inside a guest?". Those are independent questions: a physical PC can carry a complete VMware Tools installation, either because somebody installed it or because its Windows image was prepared inside a virtual machine and then deployed onto real hardware. Every signal that remains comes from the hardware and firmware themselves and cannot be produced by installing software. Where a guest driver registration is examined at all, it is believed only while that driver is actually running, since a registration alone survives an uninstall.

The resulting trade-off is deliberate and narrow. False positives on real hardware are essentially eliminated, including on a machine with both VMware Workstation and VirtualBox installed. In exchange, a guest that has hidden its CPU signature, its firmware strings and its emulated GPU vendor id but has left its guest tools installed is no longer detected; in practice that combination is self contradictory, since removing the guest tools is the first step in hardening a guest.

Some checks are platform specific and simply return false where they do not apply, so the strength of detection varies by operating system. Because no single signal is completely definitive, treat the result as a strong hint rather than absolute proof; legitimate users occasionally run inside virtual machines, and a determined attacker can hide the environment. It is most useful as one input into an anti-cheat or anti-analysis strategy rather than as a hard gate on its own.
