---
title: "Detecting DBVM from User-Mode with a Debug Exception Delivery Bug"
date: 2026-01-03
excerpt: "This article explains a user-mode DBVM detection where MOV SS delays the #DB from a data breakpoint across CPUID, DBVM's CPUID handler overwrites the pending debug state, and DR6 reports BS without B0."
tags:
  - dbvm
  - hypervisor-detection
  - debug-exceptions
  - dr6
  - mov-ss
  - hardware-breakpoints
  - vm-exit
  - cpuid
  - pending-debug-exceptions
  - user-mode
  - anti-cheat
---

## Disclaimer

This research is published for educational and defensive reverse engineering. It documents DBVM's pending-debug-exception behavior so analysts can understand the processor state involved and recognize the behavior during analysis.

It is not intended to help bypass anti-cheat enforcement, hide unauthorized software, or interfere with any game, player, publisher, or service.

Requests from the Cheat Engine project, an authorized DBVM representative, or an appropriate rights holder for correction, revision, or removal will be reviewed, and the article can be changed or taken down if appropriate.

## One Debug Exception, Two Conditions

The processor can deliver [#DB](https://wiki.osdev.org/Exceptions#Debug_Exception) for several debug conditions. This probe uses two of them: a data breakpoint and single-step execution.

Intel describes the two pieces separately in its debug facilities overview:

> "Breakpoint-address registers (DR0 through DR3) — Specifies the addresses of up to 4 breakpoints."

> "TF (trap) flag, EFLAGS register — Generates a debug exception (#DB) after every execution of an instruction."

DR0 supplies the watched address, DR7 controls what kind of access trips it, and TF asks the processor to single-step. Those inputs are independent, but they can meet at the same delivered #DB when event delivery is delayed.

## What DR6 Records

DR6 is the architectural status register for [debug exceptions](https://en.wikipedia.org/wiki/X86_debug_register#DR6_-_Debug_status). Intel describes it this way:

> "Debug status register (DR6) — Reports the conditions that were in effect when a debug or breakpoint exception was generated."

B0 through B3 are the breakpoint-condition flags. If B0 is set when #DB is delivered, the breakpoint condition associated with DR0 was met:

> "B0 through B3 (breakpoint condition detected) flags (bits 0 through 3) — Indicates (when set) that its associated breakpoint condition was met when a debug exception was generated."

The important part for this check is that BS does not exclude the breakpoint bits:

> "When the BS flag is set, any of the other debug status bits also may be set."

## The Special Handling Around MOV SS and CPUID

The probe executes [MOV SS](https://www.felixcloutier.com/x86/mov) as `mov ss, word ptr [g_ss]`. That loads SS from memory, and the memory operand is the watched `g_ss` variable. DR0 catches the read during MOV SS, but Intel delays the debug exception:

> "If an execution of the MOV or POP instruction loads the SS register and encounters a data breakpoint, the resulting debug exception is delivered after completion of the next instruction (the one after the MOV or POP)."

Single-step delivery has its own MOV SS rule:

> "Any single-step trap that would be delivered following the MOV to SS instruction or POP to SS instruction (because EFLAGS.TF is 1) is suppressed."

[CPUID](https://www.felixcloutier.com/x86/cpuid) is the next instruction. Intel lists CPUID in the unconditional VM-exit section for [VMX](<https://en.wikipedia.org/wiki/X86_virtualization#Intel_virtualization_(VT-x)>) non-root operation:

> "The following instructions cause VM exits when they are executed in VMX non-root operation: CPUID, GETSEC, INVD, and XSETBV."

That places the VM exit between the MOV SS memory access and the delayed #DB delivery. A hypervisor handling CPUID at that point has to resume the guest with the pending debug state still intact.

## Pending Debug State in the VMCS

VMX carries delayed debug exceptions through the [VMCS](https://en.wikipedia.org/wiki/Virtual_Machine_Control_Structure) pending debug-exceptions field. Intel defines the field as state for debug exceptions that have not reached the guest yet:

> "The pending debug exceptions field in the guest-state area indicates whether there are debug exceptions that have not yet been delivered (see Section 27.4.2)."

When VM entry is not injecting another event, that pending state is handled as normal guest debug state:

> "If the VM entry is not injecting, the pending debug exceptions are treated as they would had they been encountered normally in guest execution:"

> "If the logical processor is not blocking such exceptions (the interruptibility-state field indicates no blocking by MOV SS), a debug exception is delivered after VM entry (see below)."

The CPUID exit used here matches a specific MOV SS rule. CPUID is not #DB, and the guest is still in the MOV SS blocking window. Intel names that case directly:

> "VM exits that are not caused by debug exceptions and that occur while there is MOV-SS blocking of debug exceptions."

For that case, the saved value keeps the pending debug state:

> "In this case, the value saved sets bits corresponding to the causes of any debug exceptions that were pending at the time of the VM exit."

For that saved pending state, Intel describes the breakpoint bits directly:

> "Each of bits 3:0 may be set if it corresponds to a matched breakpoint. This may be true even if the corresponding breakpoint is not enabled in DR7."

> "Bit 12 (enabled breakpoint) is set to 1 if there was at least one matched data or I/O breakpoint that was enabled in DR7."

## DBVM's CPUID Handler

In [`handleCPUID`](https://github.com/cheat-engine/cheat-engine/blob/master/dbvm/vmm/vmeventhandler.c#L1923), DBVM checks guest RFLAGS, writes 0x4000 to `vm_pending_debug_exceptions` when TF is set, then emulates CPUID and advances RIP:

```c
int handleCPUID(VMRegisters *vmregisters)
{
  RFLAGS flags;
  flags.value=vmread(vm_guest_rflags);

  if (flags.TF==1)
  {
    vmwrite(vm_pending_debug_exceptions,0x4000);
  }

  _cpuid(&(vmregisters->rax),&(vmregisters->rbx),&(vmregisters->rcx),&(vmregisters->rdx));

  incrementRIP(vmread(vm_exit_instructionlength));

  getcpuinfo()->lastTSCTouch=_rdtsc();
  return 0;
}
```

0x4000 is bit 14, the BS bit, but the handler never reads the current pending debug-exceptions field or merges in the breakpoint bits left by MOV SS.

After VM entry, the processor delivers #DB from the overwritten pending state, leaving DR6 with BS set and B0 clear instead of the expected B0 and BS pair.

## Source Code

The source below sets the DR0 breakpoint, enables TF, executes `mov ss, word ptr [g_ss]`, runs CPUID, handles the resulting single-step exception, and prints DR6:

```c
#include <windows.h>
#include <stdio.h>
#include <stdint.h>

/* DR6 status register. */
typedef union {
    DWORD64 raw;
    struct {
        DWORD64 b0  : 1;  /* Breakpoint 0 condition detected. */
        DWORD64 b1  : 1;  /* Breakpoint 1 condition detected. */
        DWORD64 b2  : 1;  /* Breakpoint 2 condition detected. */
        DWORD64 b3  : 1;  /* Breakpoint 3 condition detected. */
        DWORD64 _r0 : 9;  /* Reserved.                        */
        DWORD64 bd  : 1;  /* Debug register access detected.  */
        DWORD64 bs  : 1;  /* Single step trap.                */
        DWORD64 bt  : 1;  /* Task switch.                     */
        DWORD64 _r1 : 48; /* Reserved.                        */
    };
} Dr6;

/* DR7 control register. */
typedef union {
    DWORD64 raw;
    struct {
        DWORD64 l0   : 1;  /* Local enable DR0.           */
        DWORD64 g0   : 1;  /* Global enable DR0.          */
        DWORD64 l1   : 1;  /* Local enable DR1.           */
        DWORD64 g1   : 1;  /* Global enable DR1.          */
        DWORD64 l2   : 1;  /* Local enable DR2.           */
        DWORD64 g2   : 1;  /* Global enable DR2.          */
        DWORD64 l3   : 1;  /* Local enable DR3.           */
        DWORD64 g3   : 1;  /* Global enable DR3.          */
        DWORD64 le   : 1;  /* Local exact (obsolete).     */
        DWORD64 ge   : 1;  /* Global exact (obsolete).    */
        DWORD64 _r0  : 1;  /* Reserved (1).               */
        DWORD64 rtm  : 1;  /* RTM.                        */
        DWORD64 _r1  : 1;  /* Reserved (0).               */
        DWORD64 gd   : 1;  /* General detect.             */
        DWORD64 _r2  : 2;  /* Reserved (0).               */
        DWORD64 rw0  : 2;  /* Condition DR0.              */
        DWORD64 len0 : 2;  /* Length DR0.                 */
        DWORD64 rw1  : 2;  /* Condition DR1.              */
        DWORD64 len1 : 2;  /* Length DR1.                 */
        DWORD64 rw2  : 2;  /* Condition DR2.              */
        DWORD64 len2 : 2;  /* Length DR2.                 */
        DWORD64 rw3  : 2;  /* Condition DR3.              */
        DWORD64 len3 : 2;  /* Length DR3.                 */
        DWORD64 _r3  : 32; /* Reserved.                   */
    };
} Dr7;

/* DR7 RW field values. */
typedef enum {
    DR7_RW_EXEC  = 0,  /* Break on execution.  */
    DR7_RW_WRITE = 1,  /* Break on write.      */
    DR7_RW_IO    = 2,  /* Break on I/O.        */
    DR7_RW_RW    = 3,  /* Break on read/write. */
} Dr7Rw;

/* DR7 LEN field values. */
typedef enum {
    DR7_LEN_1 = 0,  /* 1-byte length.          */
    DR7_LEN_2 = 1,  /* 2-byte length.          */
    DR7_LEN_8 = 2,  /* 8-byte length (64-bit). */
    DR7_LEN_4 = 3,  /* 4-byte length.          */
} Dr7Len;

/* EFLAGS bits. */
#define EFLAGS_TF    (1 << 8)  /* Trap flag (single-step). */

/* Global variables. */
static Dr6 g_dr6 = {0};
static WORD g_ss = 0;

LONG WINAPI veh(EXCEPTION_POINTERS *info) {
    if (info->ExceptionRecord->ExceptionCode != EXCEPTION_SINGLE_STEP)
        return EXCEPTION_CONTINUE_SEARCH;

    PCONTEXT ctx = info->ContextRecord;
    g_dr6.raw = ctx->Dr6;

    ctx->EFlags &= ~EFLAGS_TF;
    ctx->Dr0 = 0;
    ctx->Dr6 = 0;
    ctx->Dr7 = 0;

    return EXCEPTION_CONTINUE_EXECUTION;
}

void print_dr6(Dr6 dr6) {
    printf("    DR6: 0x%llX\n", dr6.raw);
    printf("        B0 (HWBP 0):      %lld\n", dr6.b0);
    printf("        B1 (HWBP 1):      %lld\n", dr6.b1);
    printf("        B2 (HWBP 2):      %lld\n", dr6.b2);
    printf("        B3 (HWBP 3):      %lld\n", dr6.b3);
    printf("        BD (DR access):   %lld\n", dr6.bd);
    printf("        BS (single-step): %lld\n", dr6.bs);
    printf("        BT (task switch): %lld\n", dr6.bt);
}

int main(void) {
    AddVectoredExceptionHandler(1, veh);

    __asm__ volatile (".intel_syntax noprefix; mov %0, ss; .att_syntax prefix" : "=r"(g_ss));

    CONTEXT ctx = { .ContextFlags = CONTEXT_DEBUG_REGISTERS };
    GetThreadContext(GetCurrentThread(), &ctx);

    Dr7 dr7 = {0};
    dr7.l0   = 1;
    dr7.g0   = 1;
    dr7.rw0  = DR7_RW_RW;
    dr7.len0 = DR7_LEN_2;
    ctx.Dr0 = (DWORD64)&g_ss;
    ctx.Dr7 = dr7.raw;
    SetThreadContext(GetCurrentThread(), &ctx);

    __asm__ volatile (
        ".intel_syntax noprefix\n"
        "push rbx\n"
        "pushfq\n"
        "or dword ptr [rsp], %c[tf]\n"
        "popfq\n"
        "mov ss, word ptr [%0]\n"
        "cpuid\n"
        "pop rbx\n"
        ".att_syntax prefix\n"
        :: "r"(&g_ss), [tf] "i"(EFLAGS_TF) : "rax", "rcx", "rdx", "memory"
    );

    int detected = !(g_dr6.bs && g_dr6.b0);
    printf("    DBVM Detected: %s\n", detected ? "true" : "false");
    print_dr6(g_dr6);

    return 0;
}
```

## Reading the Result

The following output was collected on Windows 10 22H2 with an Intel Core i7-8700. With the affected DBVM path active, DR6 reports BS without B0:

```text
C:\Users\win10\Desktop>dbvm-dtc.exe
    DBVM Detected: true
    DR6: 0xFFFF4FF0
        B0 (HWBP 0):      0
        B1 (HWBP 1):      0
        B2 (HWBP 2):      0
        B3 (HWBP 3):      0
        BD (DR access):   0
        BS (single-step): 1
        BT (task switch): 0
```

Without DBVM active on the same system, DR6 reports B0 and BS together:

```text
C:\Users\win10\Desktop>dbvm-dtc.exe
    DBVM Detected: false
    DR6: 0xFFFF4FF1
        B0 (HWBP 0):      1
        B1 (HWBP 1):      0
        B2 (HWBP 2):      0
        B3 (HWBP 3):      0
        BD (DR access):   0
        BS (single-step): 1
        BT (task switch): 0
```

## References

- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3A](https://cdrdv2.intel.com/v1/dl/getContent/671190), Section 7.8.3, "Masking Exceptions and Interrupts When Switching Stacks."
- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3B](https://cdrdv2.intel.com/v1/dl/getContent/671427), Section 20.1, "Overview of Debug Support Facilities."
- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3B](https://cdrdv2.intel.com/v1/dl/getContent/671427), Section 20.2.3, "Debug Status Register (DR6)."
- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3B](https://cdrdv2.intel.com/v1/dl/getContent/671427), Section 20.3.1.2, "Data Memory and I/O Breakpoint Exception Conditions."
- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3C](https://cdrdv2.intel.com/v1/dl/getContent/671506), Section 28.1.2, "Instructions That Cause VM Exits Unconditionally."
- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3C](https://cdrdv2.intel.com/v1/dl/getContent/671506), Section 29.7.3, "Delivery of Pending Debug Exceptions after VM Entry."
- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 3C](https://cdrdv2.intel.com/v1/dl/getContent/671506), Section 30.3.4, "Saving Non-Register State."
