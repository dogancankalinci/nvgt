/*
  AngelCode Scripting Library
  Copyright (c) 2003-2020 Andreas Jonsson

  This software is provided 'as-is', without any express or implied
  warranty. In no event will the authors be held liable for any
  damages arising from the use of this software.

  Permission is granted to anyone to use this software for any
  purpose, including commercial applications, and to alter it and
  redistribute it freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you
     must not claim that you wrote the original software. If you use
     this software in a product, an acknowledgment in the product
     documentation would be appreciated but is not required.

  2. Altered source versions must be plainly marked as such, and
     must not be misrepresented as being the original software.

  3. This notice may not be removed or altered from any source
     distribution.

  The original version of this library can be located at:
  http://www.angelcode.com/angelscript/

  Andreas Jonsson
  andreas@angelcode.com
*/

/*
   Assembly routines for the ARM call convention
   Written by Fredrik Ehnbom in June 2009

   Adapted to GNUC by darktemplar216 in September 2009

   Modified by Lasse Oorni for 8-byte stack alignment in May 2012

   ALTERED FOR NVGT: the soft-float (Android armeabi-v7a) routines of AngelScript's as_callfunc_arm_gcc.S, with ARM EHABI
   unwind information added. The original routines have none, so the linker covers them with EXIDX_CANTUNWIND and a C++
   exception thrown by a registered native function cannot unwind through them to the catch in CallSystemFunction: the
   process ends in std::terminate instead of the script getting the exception. Each routine now also saves r10 and r11 (r10
   only keeps the stack 8-byte aligned), keeps its frame in r11 for the unwinder, as the stack it hands to the callee moves by
   a variable amount, reads its fifth argument 32 bytes up instead of 24, and restores sp from r11. The stack arguments are
   copied through r12 instead of by moving sp over them, and the ObjLast routines store the object pointer through r11
   after moving sp, not before: the original left both below sp for a moment, where a signal handler running on this
   thread would overwrite them. Everything else is the original code. NVGT links this object ahead of the prebuilt
   AngelScript library, so the library's own copy is not used.
*/

#if defined(__arm__) && !defined(__aarch64__) && !defined(AS_MAX_PORTABILITY)

	.syntax unified
	.arm
	.text
	.align 2

	.global armFunc
	.type armFunc, %function
armFunc:
	.fnstart
	push	{r4, r5, r6, r7, r8, r10, r11, lr}
	.save	{r4, r5, r6, r7, r8, r10, r11, lr}
	mov	r11, sp
	.setfp	r11, sp
	mov	r6, r0
	movs	r7, r1
	mov	r4, r2
	mov	r8, #0
	beq	1f
	cmp	r7, #4
	ldrge	r0, [r6], #4
	cmp	r7, #8
	ldrge	r1, [r6], #4
	cmp	r7, #12
	ldrge	r2, [r6], #4
	cmp	r7, #16
	ldrge	r3, [r6], #4
	ble	1f
	sub	r7, r7, #16
	add	r8, r7, #4
	bic	r8, r8, #4
	sub	sp, sp, r8
	mov	r12, sp
2:	ldr	r5, [r6], #4
	str	r5, [r12], #4
	subs	r7, r7, #4
	bne	2b
1:	blx	r4
	mov	sp, r11
	pop	{r4, r5, r6, r7, r8, r10, r11, pc}
	.fnend
	.size armFunc, .-armFunc

	.global armFuncObjLast
	.type armFuncObjLast, %function
armFuncObjLast:
	.fnstart
	push	{r4, r5, r6, r7, r8, r10, r11, lr}
	.save	{r4, r5, r6, r7, r8, r10, r11, lr}
	mov	r11, sp
	.setfp	r11, sp
	mov	r6, r0
	movs	r7, r1
	mov	r4, r2
	mov	r8, #0
	mov	r0, r3
	mov	r5, r3
	beq	1f
	cmp	r7, #4
	ldrge	r0, [r6], #4
	cmp	r7, #8
	ldrge	r1, [r6], #4
	movlt	r1, r5
	cmp	r7, #12
	ldrge	r2, [r6], #4
	movlt	r2, r5
	cmp	r7, #16
	ldrge	r3, [r6], #4
	movlt	r3, r5
	blt	1f
	sub	r7, r7, #16
	add	r8, r7, #8
	bic	r8, r8, #4
	sub	sp, sp, r8
	str	r5, [r11, #-4]
	str	r5, [r11, #-8]
	cmp	r7, #0
	beq	1f
	mov	r12, sp
2:	ldr	r5, [r6], #4
	str	r5, [r12], #4
	subs	r7, r7, #4
	bne	2b
1:	blx	r4
	mov	sp, r11
	pop	{r4, r5, r6, r7, r8, r10, r11, pc}
	.fnend
	.size armFuncObjLast, .-armFuncObjLast

	.global armFuncR0ObjLast
	.type armFuncR0ObjLast, %function
armFuncR0ObjLast:
	.fnstart
	push	{r4, r5, r6, r7, r8, r10, r11, lr}
	.save	{r4, r5, r6, r7, r8, r10, r11, lr}
	mov	r11, sp
	.setfp	r11, sp
	ldr	r5, [sp, #32]
	mov	r6, r0
	movs	r7, r1
	mov	r4, r2
	mov	r8, #0
	mov	r0, r3
	mov	r1, r5
	beq	1f
	cmp	r7, #4
	ldrge	r1, [r6], #4
	cmp	r7, #8
	ldrge	r2, [r6], #4
	movlt	r2, r5
	cmp	r7, #12
	ldrge	r3, [r6], #4
	movlt	r3, r5
	blt	1f
	sub	r7, r7, #12
	add	r8, r7, #8
	bic	r8, r8, #4
	sub	sp, sp, r8
	str	r5, [r11, #-4]
	str	r5, [r11, #-8]
	cmp	r7, #0
	beq	1f
	mov	r12, sp
2:	ldr	r5, [r6], #4
	str	r5, [r12], #4
	subs	r7, r7, #4
	bne	2b
1:	blx	r4
	mov	sp, r11
	pop	{r4, r5, r6, r7, r8, r10, r11, pc}
	.fnend
	.size armFuncR0ObjLast, .-armFuncR0ObjLast

	.global armFuncR0
	.type armFuncR0, %function
armFuncR0:
	.fnstart
	push	{r4, r5, r6, r7, r8, r10, r11, lr}
	.save	{r4, r5, r6, r7, r8, r10, r11, lr}
	mov	r11, sp
	.setfp	r11, sp
	mov	r6, r0
	movs	r7, r1
	mov	r4, r2
	mov	r8, #0
	mov	r0, r3
	beq	1f
	cmp	r7, #4
	ldrge	r1, [r6], #4
	cmp	r7, #8
	ldrge	r2, [r6], #4
	cmp	r7, #12
	ldrge	r3, [r6], #4
	ble	1f
	sub	r7, r7, #12
	add	r8, r7, #4
	bic	r8, r8, #4
	sub	sp, sp, r8
	mov	r12, sp
2:	ldr	r5, [r6], #4
	str	r5, [r12], #4
	subs	r7, r7, #4
	bne	2b
1:	blx	r4
	mov	sp, r11
	pop	{r4, r5, r6, r7, r8, r10, r11, pc}
	.fnend
	.size armFuncR0, .-armFuncR0

	.global armFuncR0R1
	.type armFuncR0R1, %function
armFuncR0R1:
	.fnstart
	push	{r4, r5, r6, r7, r8, r10, r11, lr}
	.save	{r4, r5, r6, r7, r8, r10, r11, lr}
	mov	r11, sp
	.setfp	r11, sp
	mov	r6, r0
	movs	r7, r1
	mov	r4, r2
	mov	r8, #0
	mov	r0, r3
	ldr	r1, [sp, #32]
	beq	1f
	cmp	r7, #4
	ldrge	r2, [r6], #4
	cmp	r7, #8
	ldrge	r3, [r6], #4
	ble	1f
	sub	r7, r7, #8
	add	r8, r7, #4
	bic	r8, r8, #4
	sub	sp, sp, r8
	mov	r12, sp
2:	ldr	r5, [r6], #4
	str	r5, [r12], #4
	subs	r7, r7, #4
	bne	2b
1:	blx	r4
	mov	sp, r11
	pop	{r4, r5, r6, r7, r8, r10, r11, pc}
	.fnend
	.size armFuncR0R1, .-armFuncR0R1

#endif
