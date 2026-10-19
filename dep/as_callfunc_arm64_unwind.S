//
//  AngelCode Scripting Library
//  Copyright (c) 2020-2024 Andreas Jonsson
//
//  This software is provided 'as-is', without any express or implied
//  warranty. In no event will the authors be held liable for any
//  damages arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any
//  purpose, including commercial applications, and to alter it and
//  redistribute it freely, subject to the following restrictions:
//
//  1. The origin of this software must not be misrepresented; you
//     must not claim that you wrote the original software. If you use
//     this software in a product, an acknowledgment in the product
//     documentation would be appreciated but is not required.
//
//  2. Altered source versions must be plainly marked as such, and
//     must not be misrepresented as being the original software.
//
//  3. This notice may not be removed or altered from any source
//     distribution.
//
//  The original version of this library can be located at:
//  http://www.angelcode.com/angelscript/
//
//  Andreas Jonsson
//  andreas@angelcode.com
//
// Assembly routines for the ARM64/AArch64 call convention used for Linux
// Written by Max Waine in July 2020, based on as_callfunc_arm_msvc.asm,
// with assistance & guidance provided by Sir Kane
//
// ALTERED FOR NVGT: AngelScript's as_callfunc_arm64_gcc.S with its unwind information corrected. The original records x20
// as saved 16 bytes above the canonical frame address instead of below it, so an exception unwinding through these routines
// restored the caller's x20 from an unrelated stack slot, and it keeps the frame address relative to sp although sp moves
// down by the size of any stack arguments before the call, so with stack arguments the unwinder read the return address
// from among them and the process ended in std::terminate. The frame address is now taken from x29 once the frame is set up.
// The stack arguments are also copied through x12 instead of by moving sp over them, so nothing already copied is ever below
// sp, and sp is restored from x29 after the call. Everything else is the original code. NVGT links this object ahead of the
// prebuilt AngelScript library, so the library's own copy is not used.

#if defined(__aarch64__) && !defined(__APPLE__) && !defined(AS_MAX_PORTABILITY)

	.text

	.global GetHFAReturnDouble
	.global GetHFAReturnFloat
	.global CallARM64Ret128
	.global CallARM64RetInMemory
	.global CallARM64Double
	.global CallARM64Float
	.global CallARM64

	.type GetHFAReturnDouble, %function
	.type GetHFAReturnFloat, %function
	.type CallARM64Ret128, %function
	.type CallARM64RetInMemory, %function
	.type CallARM64Double, %function
	.type CallARM64Float, %function
	.type CallARM64, %function

	.align 2
GetHFAReturnDouble:
	.cfi_startproc
	adr	x9, populateDoubles
	sub	x9, x9, x2, lsr 1
	br	x9

	str	d3, [x0, #0x18]
	str	d2, [x0, #0x10]
	str	d1, [x1]
	str	d0, [x0]
populateDoubles:
	ret
	.cfi_endproc
	.size GetHFAReturnDouble, .-GetHFAReturnDouble

	.align 2
GetHFAReturnFloat:
	.cfi_startproc
	adr	x9, populateFloats
	sub	x9, x9, x2
	br	x9

	str	s3, [x1, #0x4]
	str	s2, [x1]
	str	s1, [x0, #0x4]
	str	s0, [x0]
populateFloats:
	ret
	.cfi_endproc
	.size GetHFAReturnFloat, .-GetHFAReturnFloat

	.align 2
CallARM64Double:
CallARM64Float:
CallARM64:
	.cfi_startproc
	stp	x29, x30, [sp, #-0x20]!
	.cfi_def_cfa_offset 0x20
	.cfi_offset x29, -0x20
	.cfi_offset x30, -0x18
	str	x20, [sp, #0x10]
	.cfi_offset x20, -0x10
	mov	x29, sp
	.cfi_def_cfa_register x29

	mov	x20, #0

	cbz	x5, stackArgsLoopEnd

	add	x20, x5, #1
	lsl	x20, x20, #3
	and	x20, x20, #-0x10
	lsl	x10, x5, #3
	sub	sp, sp, x20
	mov	x12, sp
stackArgsLoopStart:
	ldp	x9, x11, [x4], #16
	stp	x9, x11, [x12], #16
	subs	x10, x10, #16
	b.gt	stackArgsLoopStart
stackArgsLoopEnd:

	adr	x9, populateFloatRegisterArgsEnd
	sub	x9, x9, x3, lsl 2
	br	x9

	ldr	d7, [x2, #0x38]
	ldr	d6, [x2, #0x30]
	ldr	d5, [x2, #0x28]
	ldr	d4, [x2, #0x20]
	ldr	d3, [x2, #0x18]
	ldr	d2, [x2, #0x10]
	ldr	d1, [x2, #0x08]
	ldr	d0, [x2]
populateFloatRegisterArgsEnd:

	mov	x15, x6
	adr	x9, populateGPRegisterArgsEnd
	sub	x9, x9, x1, lsl 2
	br	x9

	ldr	x7, [x0, #0x38]
	ldr	x6, [x0, #0x30]
	ldr	x5, [x0, #0x28]
	ldr	x4, [x0, #0x20]
	ldr	x3, [x0, #0x18]
	ldr	x2, [x0, #0x10]
	ldr	x1, [x0, #0x08]
	ldr	x0, [x0]
populateGPRegisterArgsEnd:

	blr	x15
	mov	sp, x29

	ldr	x20, [sp, #0x10]
	ldp	x29, x30, [sp], #0x20
	.cfi_def_cfa sp, 0
	.cfi_restore x30
	.cfi_restore x29
	.cfi_restore x20
	ret
	.cfi_endproc
	.size CallARM64, .-CallARM64

	.align 2
CallARM64Ret128:
	.cfi_startproc
	stp	x29, x30, [sp, #-0x20]!
	.cfi_def_cfa_offset 0x20
	.cfi_offset x29, -0x20
	.cfi_offset x30, -0x18
	str	x20, [sp, #0x10]
	.cfi_offset x20, -0x10
	mov	x29, sp

	mov	x20, x6
	mov	x6, x7
	mov	x7, #0
	bl	CallARM64

	str	x1, [x20]

	ldr	x20, [sp, #0x10]
	ldp	x29, x30, [sp], #0x20
	.cfi_def_cfa_offset 0
	.cfi_restore x30
	.cfi_restore x29
	.cfi_restore x20
	ret
	.cfi_endproc
	.size CallARM64Ret128, .-CallARM64Ret128

	.align 2
CallARM64RetInMemory:
	.cfi_startproc
	stp	x29, x30, [sp, #-0x10]!
	.cfi_def_cfa_offset 0x10
	.cfi_offset x29, -0x10
	.cfi_offset x30, -0x08
	mov	x29, sp

	mov	x8, x6
	mov	x6, x7
	mov	x7, #0
	bl	CallARM64

	mov	x0, x8

	ldp	x29, x30, [sp], #0x10
	.cfi_def_cfa_offset 0
	.cfi_restore x30
	.cfi_restore x29
	ret
	.cfi_endproc
	.size CallARM64RetInMemory, .-CallARM64RetInMemory

#endif
