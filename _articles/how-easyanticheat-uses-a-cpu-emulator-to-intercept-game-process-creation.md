---
title: "How EasyAntiCheat Uses a CPU Emulator to Intercept Game Process Creation"
date: 2023-07-07
excerpt: "EasyAntiCheat embeds a CPU emulator in its kernel driver. During game process creation, the emulator follows the NtCreateUserProcess path far enough to intercept the DirectoryTableBase write before process callbacks observe it."
tags:
  - easyanticheat
  - reverse-engineering
  - kernel-mode
  - cpu-emulation
  - ntcreateuserprocess
  - mmcreateprocessaddressspace
  - eprocess
  - cr3
  - ept
  - anti-cheat
  - process-creation
---

## Disclaimer

This research is published for educational and defensive reverse engineering. It documents an EasyAntiCheat process-creation technique so analysts can understand the Windows internals involved and recognize the behavior during analysis.

It is not intended to help bypass anti-cheat enforcement, hide unauthorized software, or interfere with any game, player, publisher, or service.

Requests from Epic Games, an authorized EasyAntiCheat representative, or an appropriate rights holder for correction, revision, or removal will be reviewed, and the article can be changed or taken down if appropriate.

## DirectoryTableBase and CR3

Windows gives each user-mode process its own private virtual address space. Microsoft describes the debugger-facing version of the same idea in the [`.context` command](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-context--set-user-mode-address-context-): it "specifies which page directory of a process" the debugger uses as the user-mode address context.

On x86-64 Windows, the process paging root is stored in the embedded `KPROCESS` portion of `EPROCESS`, at `EPROCESS.Pcb.DirectoryTableBase`. Intel's system programming guide describes the hardware side directly: "The base physical address of the paging-structure hierarchy is contained in control register CR3." In practical terms, the value at offset `0x28` in this sampled `EPROCESS` decides which user-mode address translations are active for that process.

## Callback Timing

Microsoft documents [`PsSetCreateProcessNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine) as the routine that adds a driver callback to the list called when a process is created or deleted. For creates, the callback is called "just after the initial thread is created." The [`PCREATE_PROCESS_NOTIFY_ROUTINE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine) page also says the create callback "runs in the context of the thread" that created the process.

That timing is already too late for this case. A callback registered through the normal process notification path sees the modified `DirectoryTableBase`:

```
#   Time          Debug Print
92  65.96354675   [Chimera] Process: RustClient.exe
93  65.96356201   [Chimera] CR3: 40000008543f4000
```

Hooks around `PspInsertProcess` show the same thing. The process object is already carrying the EasyAntiCheat value by the time the callback path observes it. The write has to happen earlier, before process notify callbacks are reached.

## Where Windows Writes the Paging Root

The first useful Windows-side target is `MmCreateProcessAddressSpace`. In the observed build, this is where the address-space root is written into the new process object:

```cpp
*(_QWORD *)(Process + 0x28) = KeMakeKernelDirectoryTableBase(TopLevelPage << 12);
```

This gives the investigation a concrete split. Either Windows writes the original value and EasyAntiCheat patches it later, or EasyAntiCheat intercepts the store path before the original value lands in `EPROCESS`.

A process-local hook can answer that, but it brings page-table complications into the launcher. An EPT write trap is cleaner because it watches the physical page that backs the new `EPROCESS`, regardless of which virtual address the writer uses.

## Trapping the New EPROCESS Page

The trap is installed after the new `EPROCESS` allocation is known. At this point in the launch path, the current process is the launcher, so the hook filters for the launcher image name and then marks the `EPROCESS` page read-only with Extended Page Tables (EPT):

```cpp
void PspInitializeProcessLockHook( uintptr_t Process )
{
    *( uint64_t* )( Process + 0x438 ) = 0;

    uintptr_t CurrentProcess = uintptr_t( PsGetCurrentProcess( ) );
    PCHAR ImageFileName = PCHAR( CurrentProcess ) + 0x5A8;

    if ( strcmp( ImageFileName, "Rust.exe" ) == 0 )
    {
        ::Process = Process;
        AddEptHook( Process, HvDebugger::HvAccess::Write, ProcessWatch );
    }
}
```

The trap covers a whole physical page, and the `EPROCESS` allocation does not need to begin on a page boundary. The handler checks that the faulting write falls inside the expected process object range, then filters for writes coming from the EasyAntiCheat image:

```cpp
bool ProcessWatch( HvDebugger::HvContext* Context, uintptr_t Address, uint64_t& Pfn )
{
    if ( Address >= Process && Address <= Process + 0xA40 )
    {
        if ( Context->Rip >= EacBase && Context->Rip <= EacBase + EacSize )
        {
            uint16_t Offset = Address - Process;

            if ( Offset == 0x28 )
                WriteLog( "ProcessWatch", TraceLoggingHexUInt64( Context->Rip - EacBase, "Rva" ), ...Other Registers... );
        }
    }

    return false;
}
```

That trap catches an EasyAntiCheat write to offset `0x28`:

```json
{ "Rva":"0x58233A", "Rbp": "0x4000000853FFF000", ...Other Registers... }
```

The writer resolves to this virtualized store:

```asm
seg007:0000000000582336 mov     rbp, [rsp+r8+0]        ; Read the manipulated CR3.
seg007:000000000058233A mov     [rbx], rbp             ; Write the manipulated CR3.
seg007:000000000058233D movsxd  rbx, dword ptr [rsp+0] ; Calculate, and jump to the next handler.
seg007:0000000000582341 mov     rbp, rax
seg007:0000000000582344 and     rbp, rbx
seg007:0000000000582347 mov     rcx, rbx
seg007:000000000058234A shr     rbp, cl
seg007:000000000058234D xor     ecx, ecx
seg007:000000000058234F add     rdx, rbx
seg007:0000000000582352 cmp     rbx, 40h ; '@'
seg007:0000000000582356 cmovnb  rbp, rcx
seg007:000000000058235A xor     rdx, rbp
seg007:000000000058235D add     rsp, 4
seg007:0000000000582361 mov     rcx, rdx
seg007:0000000000582364 mov     r8, rdi
seg007:0000000000582367 jmp     rcx
```

The instruction at `0x58233A` is the store to `EPROCESS.Pcb.DirectoryTableBase`. The previous instruction loads the transformed CR3 value from a stack slot. That is the first direct evidence that EasyAntiCheat writes the protected value itself instead of waiting for Windows to complete the original store.

## Register-Sized Write Primitive

The `DirectoryTableBase` write is not the only `EPROCESS` write performed through this path. Removing the `0x28` filter shows the same EasyAntiCheat RVA writing several fields:

```json
{ "Rva":"0x42106", "Offset":"0x5E8" }
{ "Rva":"0x42106", "Offset":"0x5E0" }
{ "Rva":"0x42106", "Offset":"0x8A8" }
{ "Rva":"0x42106", "Offset":"0x8A0" }
{ "Rva":"0x42106", "Offset":"0x998" }
{ "Rva":"0x42106", "Offset":"0x990" }
```

That RVA lands in a size-based write primitive:

```cpp
switch ( *(_WORD *)(a2 + 20) )
{
  case 8:
    *(_BYTE *)v7 = *(_BYTE *)a3;
    break;
  case 16:
    *(_WORD *)v7 = *(_WORD *)a3;
    break;
  case 32:
    *(_DWORD *)v7 = *(_DWORD *)a3;
    break;
  case 64:
    *(_QWORD *)v7 = *(_QWORD *)a3;
    break;
  case 128:
    *(_QWORD *)v7 = *(_QWORD *)a3;
    *(_QWORD *)(v7 + 8) = *(_QWORD *)(a3 + 8);
    break;
  default:
    __fastfail(0x2CFu);
}
```

The helper writes 8, 16, 32, 64, or 128 bits from one buffer into another. That is the shape of a general instruction-emulation primitive, not a one-off field patcher.

The return address gives the caller:

```asm
.text:000000000004211E add     rsp, 30h
.text:0000000000042122 pop     rdi
.text:0000000000042123 retn
```

```cpp
uintptr_t ReturnAddress1 = Context->Rsp + 0x38;
uint32_t  ReturnAddress  = *( uintptr_t* )ReturnAddress1 - EacBase;
```

The parent function is an instruction-semantic dispatcher. Two cases identify it quickly.

One case implements `CPUID` by executing the native instruction and copying the architectural outputs back into the emulated register state:

```cpp
case 0x6B:
  _RAX = *(unsigned int *)(a1 + 8);
  __asm { cpuid }
  *(_QWORD *)(a1 + 8) = (int)_RAX;
  *(_QWORD *)(a1 + 32) = (int)_RBX;
  *(_QWORD *)(a1 + 16) = (int)_RCX;
  *(_QWORD *)(a1 + 24) = (int)_RDX;
  goto LABEL_440;
```

Another case implements `WRMSR`. It builds the 64-bit MSR value from `EDX:EAX`, takes the MSR index from `ECX`, and performs the write:

```cpp
case 0x634:
  __writemsr(
    *(_DWORD *)(a1 + 16),
    *(unsigned int *)(a1 + 8) | ((unsigned __int64)*(unsigned int *)(a1 + 24) << 32));
  goto LABEL_440;
```

At this point the mechanism is clear enough to name: EasyAntiCheat has a CPU emulator in the kernel driver. It can interpret instruction semantics, update an emulated CPU context, and call out to native CPU instructions when needed.

## Dispatch Around the Emulator

The instruction emulator is reached through EasyAntiCheat's obfuscation virtual machine. The surrounding code decides whether a target should stay in the emulator or run as a native call:

```cpp
WasEmulated = EAC::EmulateFunction((unsigned int *)&a1→unsigned___int80, &ShouldCall, &Function);
if ( WasEmulated && ShouldCall )
  EAC::CallFunctionFromEmulator(Function, (__int64 *)&a1→_Eax, (__int128 *)a1→gap90);
return WasEmulated;
```

```cpp
EmulateCode = a2;
v3 = _InterlockedExchange64((volatile __int64 *)&EmulateCode, (__int64)EAC::EmulateCode);
v4 = 0xFFFFFFFFF80AF60Bui64;
if ( !((unsigned __int8 (__fastcall *)(__int64, __int64))EmulateCode)(v2 + 0x70, v3) )
  v4 = 0xFFFFFFFFF844BC37ui64;
  __asm { jmp     r14 }
```

The obfuscated handler behaves like `BRANCHCALL`. When emulation succeeds, the branch uses the constant `0xFFFFFFFFF844BC37`:

```asm
seg007:000000000D3C6A6 loc_D3C6A6:                             ; CODE XREF: sub_42267B+24↑j
seg007:000000000D3C6A6                                         ; seg007:000000000074003F↑j ...
seg007:000000000D3C6A6 push    rax
seg007:000000000D3C6A7 lea     rax, cs:8373070h
seg007:000000000D3C6AE lea     r14, [r14+rax]
seg007:000000000D3C6B2 pop     rax
seg007:000000000D3C6B3 jmp     r14
```

Adding the constants reaches an `EXIT` handler:

```asm
seg007:000000000099B081 ; ---------------------------------------------------------
seg007:000000000099B08E pop     r14
seg007:000000000099B091 mov     rbx, [rbp+260h]
seg007:000000000099B098 mov     rsi, [rbp+268h]
seg007:000000000099B09F mov     rdi, [rbp+270h]
seg007:000000000099B0A6 mov     r12, [rbp+278h]
seg007:000000000099B0AD mov     qword ptr [rbp+0], 0
seg007:000000000099B0B5 lea     rsp, [rbp+240h]
seg007:000000000099B0BC pop     r15
seg007:000000000099B0BE pop     r14
seg007:000000000099B0C0 pop     rbp
seg007:000000000099B0C1 retn
seg007:000000000099B0C1
```

The other branch continues dispatching more emulated instructions.

## Emulated RIP Window

The next useful boundary is the range of guest instructions that the emulator actually walks. A hook on `BRANCHCALL` can log the emulated instruction pointer from the CPU context on each dispatch:

```cpp
uintptr_t CpuContext = Context->Gpr->rbp + 0x70;
uintptr_t vRip = *( uintptr_t* )( CpuContext + 0x88 );
```

```json
{ "vRip":"0xFFFFF80681274376" }
{ "vRip":"0xFFFFF80681274379" }
{ "vRip":"0xFFFFF8068127437E" }
{ "vRip":"0xFFFFF80681274385" }
{ "vRip":"0xFFFFF80681274387" }
{ "vRip":"0xFFFFF80681274389" }
{ "vRip":"0xFFFFF8068127438B" }
{ "vRip":"0xFFFFF8068127438D" }
{ "vRip":"0xFFFFF8068127438E" }
{ "vRip":"0xFFFFF8068127438F" }
{ "vRip":"0xFFFFF80681274390" }
{ "vRip":"0xFFFFF80681274391" }
{ "vRip":"0x0000000000000000" }
```

Those addresses sit in the top-level `NtCreateUserProcess` path. The final virtual instruction pointer is zero, which acts as the termination sentinel in this sample. The emulated return path writes zero as the next address, and the dispatch loop exits when it reaches that value.

## CR3 Replacement Handler

The emulator context contains a function pointer table. One entry is more interesting than the others because it checks the emulated instruction pointer before allowing the normal instruction handler to continue:

```cpp
v10 = *(unsigned __int8 (__fastcall **)(__int64, char *))(a1 + 0x1B0);
if ( v10 && v10(a1, InstrData) )
  return v6;
```

That pointer reaches this handler:

```cpp
if ( a1->Rip != qword_185120 )
  return 0;
v4 = VM_Read((__int64)a1, *(_DWORD *)(a2 + 0x50));
v6 = VM_Read(v5, *(_DWORD *)(a2 + 0xA8));
if ( !(unsigned __int8)((__int64 (__fastcall *)(__int64, __int64))Virtualized_IsValid)(v4, v6) )
  return 0;
((void (__fastcall *)(__int64))Virtualized_SetCr3)(v4);
a1->Rip += *(unsigned __int8 *)(a2 + 8);
return 1;
```

The handler is specific to one emulated instruction pointer. It reads the operands from the emulator context, validates them, calls `Virtualized_SetCr3`, advances the emulated RIP, and reports that it handled the instruction.

This is the bridge between the high-level Windows path and the earlier EPT observation. The selected emulated instruction corresponds to the write inside `MmCreateProcessAddressSpace`, and `Virtualized_SetCr3` supplies the value that later appears at `EPROCESS.Pcb.DirectoryTableBase`.

## Native Function Fallback

EasyAntiCheat does not emulate every subroutine reachable from `NtCreateUserProcess`. The call-dispatch logic first asks an allow-list function whether the target belongs to the emulated set:

```cpp
v1 = *(unsigned __int8 (__fastcall **)(__int64, _QWORD))(a1 + 0x1A8);
FunctionToCall = v100;
if ( v1 && v1(a1, v100) )                // Should the call be emulated?
{
  *(_QWORD *)(a1 + 0x28) -= 8i64;        // Set the return address
  **(_QWORD **)(a1 + 0x28) = *_Rip;
  *_Rip = FunctionToCall;
}
else
{
  *CallRealFunction = 1;
  *RealFunction = FunctionToCall;
}
goto LABEL_440;
```

When the target is outside that list, the framework calls the real function directly:

```cpp
WasEmulated = EAC::EmulateFunction((__int64)a1, &CallRealFunction, &RealFunction);
if ( WasEmulated && CallRealFunction )
  EAC::CallRealFunction(RealFunction, (__int64 *)&a1->Eax, (__int128 *)a1->gap90);
```

The allow-list itself is just a scan over the selected function table:

```cpp
if ( !EmulatedFunctionsCount )
  return 0;
for ( i = (__int64)&EmulatedFunctions; *(_QWORD *)i != a2; i += 0x100i64 )
{
  if ( ++v2 >= (unsigned __int64)EmulatedFunctionsCount )
    return 0;
}
return 1;
```

Only calls listed in `EmulatedFunctions` stay inside the CPU emulator. In the observed build, that list selects the path that reaches `MmCreateProcessAddressSpace`. Other calls run on the real processor through the native-call helper.

That explains the timing seen from process callbacks. EasyAntiCheat does not need to emulate all of process creation. It only needs to keep enough of the `NtCreateUserProcess` path under emulation to catch the `DirectoryTableBase` initialization, substitute its protected value, and then let the rest of the path continue normally.

## Control Flow From the Trace

The modified value is present before process notify callbacks can read the new process object. The write to `EPROCESS.Pcb.DirectoryTableBase` comes from EasyAntiCheat's virtualized code, and the surrounding code is a real instruction emulator with handlers for architectural operations such as `CPUID` and `WRMSR`.

The EPT trap is only an observation tool in this analysis. EasyAntiCheat's interception mechanism is separate: an obfuscation VM routes selected `NtCreateUserProcess` instructions through a CPU emulator, uses a special handler at the `MmCreateProcessAddressSpace` write point, and stores the transformed CR3 value into the new `EPROCESS`.

Recovering the original directory-table base is a separate problem. It requires either finding the real paging root elsewhere or reversing the EasyAntiCheat transformation that produces the stored value.

## References

- [Virtual Address Spaces](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces), Microsoft Learn.
- [`.context` Set User-Mode Address Context](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-context--set-user-mode-address-context-), Microsoft Learn.
- [`PsSetCreateProcessNotifyRoutine`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nf-ntddk-pssetcreateprocessnotifyroutine), Microsoft Learn.
- [`PCREATE_PROCESS_NOTIFY_ROUTINE`](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/nc-ntddk-pcreate_process_notify_routine), Microsoft Learn.
- [Intel 64 and IA-32 Architectures Software Developer Manuals](https://www.intel.com/content/www/us/en/developer/articles/technical/intel-sdm.html), Intel.
