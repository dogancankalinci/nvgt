; vmware_backdoor.asm - VMware "backdoor" I/O probe for x64 Windows (MASM / ml64).
;
; NVGT - NonVisual Gaming Toolkit
; Copyright (c) 2022-2026 Sam Tupy
; https://nvgt.dev
; This software is provided "as-is", without any express or implied warranty. In no event will the authors be held liable for any damages arising from the use of this software.
; Permission is granted to anyone to use this software for any purpose, including commercial applications, and to alter it and redistribute it freely, subject to the following restrictions:
; 1. The origin of this software must not be misrepresented; you must not claim that you wrote the original software. If you use this software in a product, an acknowledgment in the product documentation would be appreciated but is not required.
; 2. Altered source versions must be plainly marked as such, and must not be misrepresented as being the original software.
; 3. This notice may not be removed or altered from any source distribution.
;
; The MSVC toolchain has no inline assembly on x64, so the anti-cheat's VMware
; backdoor check (src/anticheat.cpp, is_vm()) calls this stub instead. It loads the
; VMware backdoor magic/command/port and executes the privileged IN instruction:
;   - On a VMware guest the hypervisor intercepts port 0x5658 and leaves the magic
;     0x564D5868 ('VMXh') in EBX, which this function returns.
;   - On real hardware the ring-3 IN raises a general-protection fault (#GP). The
;     C++ caller wraps the call in __try/__except and treats the fault as "not VMware".
;
; The PROC FRAME + .pushreg/.endprolog directives emit unwind data so that, when the
; IN faults, the Windows exception unwinder restores the caller's RBX (a non-volatile
; register we clobber to read the backdoor reply) before running the __except handler.

.code

; extern "C" unsigned int vmware_backdoor_probe(void);
vmware_backdoor_probe PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog
    mov eax, 564D5868h      ; 'VMXh' magic value
    xor ebx, ebx            ; scratch; the backdoor overwrites it with the magic
    mov ecx, 0Ah            ; command 0x0A = GETVERSION
    mov edx, 5658h          ; 'VX' backdoor port
    in  eax, dx             ; #GP on bare metal (caught by SEH in the caller)
    mov eax, ebx            ; return whatever the backdoor left in EBX
    pop rbx
    ret
vmware_backdoor_probe ENDP

END
