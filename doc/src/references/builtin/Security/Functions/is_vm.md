# is_vm
Determine whether the application appears to be running inside a virtual machine or analysis (sandbox) environment.

`bool is_vm();`

## Returns:
bool: true if a virtualized or sandboxed environment is detected, false otherwise.

## Remarks:
This function runs several independent checks and returns true if any one of them matches, so a single positive result is enough to report a virtual machine. Depending on the platform it may inspect the system model/hardware string for known hypervisor vendor names (such as VMware, VirtualBox, Hyper-V, KVM, or QEMU), look for guest-tool file artifacts left behind by virtualization software, examine the CPU's hypervisor-present feature bit, and check for the Windows Sandbox profile marker.

Some of these checks are platform specific and simply return false where they do not apply (for example, the Windows Sandbox check only runs on Windows), so the reliability of detection varies by operating system. Because none of these signals is completely definitive, treat the result as a strong hint rather than absolute proof; legitimate users occasionally run inside virtual machines, and determined attackers can hide the environment. It is most useful as one input into an anti-cheat or anti-analysis strategy rather than as a hard gate on its own.
