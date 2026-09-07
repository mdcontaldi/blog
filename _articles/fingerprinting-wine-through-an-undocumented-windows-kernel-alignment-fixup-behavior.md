---
title: "Fingerprinting Wine Through an Undocumented Windows Kernel Alignment-Fixup Behavior"
date: 2025-12-12
excerpt: "This article explores a Wine fingerprint based on Windows' alignment-fault fixup for MOVAPS. With SEM_NOALIGNMENTFAULTEXCEPT enabled, native x64 Windows can rewrite the faulting opcode to MOVUPS, while Wine leaves the instruction unchanged."
tags:
  - wine-detection
  - windows-internals
  - sse
  - movaps
  - kiop_movaps
  - alignment-fault
  - instruction-patching
  - anti-cheat
  - user-mode
  - linux
---

## How Windows Handles Alignment Faults

Windows exposes process-wide alignment-fault recovery through [`SEM_NOALIGNMENTFAULTEXCEPT`](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode). When the flag is supported, the system can fix memory alignment faults and keep them invisible to the application, but the documentation does not say how Windows does this. In this case, the recovery happens through an opcode patch.

## MOVAPS Alignment Requirements

The behavior depends on two SSE instructions that move packed single-precision floating-point values between XMM registers and 128-bit memory operands. [MOVAPS](https://www.felixcloutier.com/x86/movaps) is the aligned form, while [MOVUPS](https://www.felixcloutier.com/x86/movups) is the unaligned form.

For MOVAPS, Intel makes the alignment requirement explicit:

> "When the source or destination operand is a memory operand, the operand must be aligned on a 16-byte boundary or a general-protection exception (#GP) will be generated."

MOVUPS is the unaligned form of the same operation:

> "When the source or destination operand is a memory operand, the operand may be unaligned without causing a general-protection exception (#GP) to be generated."

For the SSE forms used here, the aligned and unaligned encodings differ only in the second opcode byte:

| Instruction form | Load opcode | Store opcode |
| --- | --- | --- |
| MOVAPS | `0F 28 /r` | `0F 29 /r` |
| MOVUPS | `0F 10 /r` | `0F 11 /r` |

## How KiOp_MOVAPS Fixes Alignment Faults

The Windows Research Kernel includes a [`KiOp_MOVAPS` handler](https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/ke/amd64/decode.c#L1610) for faulting MOVAPS instructions. It checks whether the fault came from a user-mode context with alignment fixups enabled, chooses the matching MOVUPS opcode byte, patches the instruction through [`KiOpPatchCode`](https://github.com/mic101/windows/blob/master/WRK-v1.2/base/ntos/ke/amd64/decode.c#L2086), and asks the fault path to retry.

The code checks the execution mode and auto-alignment state first. If the fixup is allowed, it maps MOVAPS load/store opcodes to the corresponding MOVUPS load/store opcodes, patches the opcode byte, and marks the instruction for retry:

```c
NTSTATUS
KiOpPatchCode(
    IN PDECODE_CONTEXT DecodeContext,
    OUT PUCHAR Destination,
    IN UCHAR Replacement
);

NTSTATUS
KiOp_MOVAPS(
    IN PDECODE_CONTEXT DecodeContext
)
{
    PKPROCESS currentProcess;
    PKTHREAD currentThread;
    UCHAR newByte;
    NTSTATUS status;

    //
    // If the current process is wow64 or has autoalignment disabled, or
    // if the fault occurred in kernel mode, then do not perform the
    // transformation.
    //

    if ((DecodeContext->CompatibilityMode != FALSE) ||
        (DecodeContext->PreviousMode != UserMode)) {

        return STATUS_SUCCESS;
    }

    currentThread = KeGetCurrentThread();
    currentProcess = currentThread->ApcState.Process;
    if ((currentThread->AutoAlignment == FALSE) &&
        (currentProcess->AutoAlignment == FALSE)) {

        return STATUS_SUCCESS;
    }

    //
    // Replace:
    //
    // 0F 28 /r - MOVAPS xmm1,xmm2/mem128
    // 0F 29 /r - MOVAPS xmm1/mem128,xmm2
    //
    // With:
    //
    // 0F 10 /r - MOVUPS xmm1,xmm2/mem128
    // 0F 11 /r - MOVUPS xmm1/mem128,xmm2
    //

    if (DecodeContext->OpCode == 0x28) {
        newByte = 0x10;
    } else {
        newByte = 0x11;
    }

    status = KiOpPatchCode(DecodeContext,
                           DecodeContext->OpCodeLocation,
                           newByte);

    if (NT_SUCCESS(status) || (status == STATUS_RETRY)) {
        DecodeContext->Retry = TRUE;
        status = STATUS_SUCCESS;
    }

    return status;
}
```

## Wine Behavior

[Wine](https://www.winehq.org/about) runs Windows applications by translating the Windows user-mode interface onto a POSIX host. That works for documented behavior, but this check depends on an undocumented kernel-side effect where Windows hides the fault by rewriting the instruction from MOVAPS to MOVUPS.

On Wine in the tested configuration, no equivalent opcode rewrite occurs. The fault becomes visible to the program as an [access violation](https://learn.microsoft.com/en-us/shows/inside/c0000005).

## Implementation

The test builds one fault and then reads one byte:

1. Place `0F 28 01 C3` as a raw instruction stub in executable code.
2. Enable `SEM_NOALIGNMENTFAULTEXCEPT` for the process.
3. Allocate a 16-byte-aligned buffer and pass `buffer + 1` to the stub, making the memory operand intentionally misaligned.
4. Catch any application-visible exception with SEH and compare the second byte of the stub.

```c
#include <windows.h>
#include <stdio.h>

#pragma section(".text")
__declspec(allocate(".text"))
static unsigned char movaps_stub[] =
{
    0x0F, 0x28, 0x01,       /* movaps xmm0, XMMWORD PTR [rcx] */
    0xC3                    /* ret                            */
};

typedef void (*movaps_fn)(void*);

static void print_hex(const char* label, const unsigned char* code, int count)
{
    printf("  %s:", label);
    for (int i = 0; i < count; i++)
        printf(" %02X", code[i]);
    printf("\n");
}

int main(void)
{
    SetErrorMode(SEM_NOALIGNMENTFAULTEXCEPT);

    __declspec(align(16)) unsigned char buffer[32] = { 0 };
    void* misaligned = buffer + 1;

    printf("\n");
    printf("  MOVAPS Alignment Fault Detection\n");
    printf("  =================================\n\n");

    print_hex("Before", movaps_stub, sizeof(movaps_stub));

    __try
    {
        ((movaps_fn)movaps_stub)(misaligned);

        print_hex("After ", movaps_stub, sizeof(movaps_stub));
        printf("\n");
        printf("  [+] Result: Native Windows\n");
        printf("      Kernel patched MOVAPS -> MOVUPS\n");
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        print_hex("After ", movaps_stub, sizeof(movaps_stub));
        printf("\n");
        printf("  [!] Result: Wine Detected\n");
        printf("      Exception 0x%08lX not handled by kernel\n",
            (unsigned long)GetExceptionCode());
    }

    printf("\n");
    return 0;
}
```

## Results

This result was collected on Windows 10 22H2 with an Intel Core i7-8700:

```
C:\Users\user\source\repos\WinePoC\x64\Release>WinePoC.exe

  MOVAPS Alignment Fault Detection
  =================================

  Before: 0F 28 01 C3
  After : 0F 10 01 C3

  [+] Result: Native Windows
      Kernel patched MOVAPS -> MOVUPS
```

This result was collected on Fedora 43 with Wine and an Intel Core i5-14400F:

```
⬢ [user@toolbx ~]$ wine WinePoC.exe

  MOVAPS Alignment Fault Detection
  =================================

  Before: 0F 28 01 C3
  After : 0F 28 01 C3

  [!] Result: Wine Detected
      Exception 0xC0000005 not handled by kernel
```

## References

- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 2B](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf), Instruction Set Reference, "MOVAPS - Move Aligned Packed Single Precision Floating-Point Values."
- [Intel® 64 and IA-32 Architectures Software Developer's Manual, Volume 2B](https://cdrdv2-public.intel.com/782151/253667-sdm-vol-2b.pdf), Instruction Set Reference, "MOVUPS - Move Unaligned Packed Single Precision Floating-Point Values."
