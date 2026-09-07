---
title: "Reverse Engineering EasyAntiCheat's Exception-Based Address-Space Protection"
date: 2023-04-26
excerpt: "This article reverse-engineers the system-wide exception hook that EasyAntiCheat uses across Windows versions. It shows how the hook intercepts context switches into protected games and makes unauthorized memory access harder."
tags:
  - easyanticheat
  - reverse-engineering
  - windows-kernel
  - cr3
  - directory-table-base
  - context-switch
  - general-protection-exception
  - hal
  - dma
  - exception-handling
  - anti-cheat
---

## Disclaimer

This research is published for educational and defensive reverse engineering. It documents EasyAntiCheat's exception-based address-space protection so analysts can understand the Windows internals involved and recognize the behavior during analysis.

It is not intended to help bypass anti-cheat enforcement, hide unauthorized software, or interfere with any game, player, publisher, or service.

Requests from Epic Games, an authorized EasyAntiCheat representative, or an appropriate rights holder for correction, revision, or removal will be reviewed, and the article can be changed or taken down if appropriate.

## How Windows Selects an Address Space

Windows gives each user-mode process its own [private virtual address space](https://learn.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/virtual-address-spaces). Kernel-mode code shares system space, but it still runs in the context of the current process when it accesses that process's user-mode addresses.

The processor translates virtual addresses through a hierarchy of paging structures. Windows stores the process paging root in the embedded [`KPROCESS`](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_KPROCESS) portion of [`EPROCESS`](https://www.vergiliusproject.com/kernels/x64/windows-10/22h2/_EPROCESS), at `EPROCESS.Pcb.DirectoryTableBase`. During a process-context switch, the thread scheduler loads the target process's directory-table base into [CR3](https://en.wikipedia.org/wiki/Control_register#CR3). That CR3 load selects the user-mode virtual address space that the processor uses for translation.

Microsoft's debugger documentation exposes the same concept through the [`PageDirectoryBase` argument to `.context`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debuggercmds/-context--set-user-mode-address-context-). The command selects the page directory that the debugger uses as the user-mode address context. The page tables for that address space then define how user-mode addresses are interpreted.

## Vanguard's Approach

Vanguard takes a similar approach to hiding game memory, but it does so by hooking a writable pointer in `.data` that Windows calls during a context switch, keeping a separate page-table hierarchy and writing its CR3 value only for selected threads.

For the full guarded-regions analysis, see [Xyrem's writeup](https://reversing.info/posts/guardedregions/). The pseudocode below keeps only the part needed for this comparison:

```cpp
// Sanity checks to check if its executing under the game's context.
if ( PsGetThreadProcess(CurrentThread) != Data::GameProcess
  || __readcr3() != Data::GameCR3 )
  return;

bool WriteToCR3 = true;

// Disabling interrupts, so that the scheduler doesn't switch cores.
_disable();

// Copying the content of the current game cr3 to the new cloned cr3.
memmove(Data::CloneVirtCR3, Data::VirtGameCR3, 0x1000);

Data::CloneVirtCR3[Data::FreePML4Index] = Data::ShadowPML4Value;

// Loop through the whitelisted threads array, and if the current running thread,
// is inside it, then allow cr3 overwrite.
for ( int ThreadIdx = 0; ThreadIdx < Data::ThreadCount; ThreadIdx++ )
{
    WriteToCR3 = Data::ThreadArray[ThreadIdx] == CurrentThread;
    
    if ( WriteToCR3 )
      break;
}

DoTask:
// Writing the cr3 to the clone cr3.
if ( WriteToCR3 )
  __writecr3(Data::CloneCR3);

// Flushing TLB by toggling CR4:PGE.
if ( CanFlushTLB )
{
  uint64_t OriginalCR4 = __readcr4();
  __writecr4(OriginalCR4 ^ 0x80);
  __writecr4(OriginalCR4);  
}

// Enabling interrupts.
_enable();
```

## EasyAntiCheat's Approach

EasyAntiCheat hides the game's address space differently. Rather than maintaining an address-space clone for selected threads, it stores an invalid value in `EPROCESS.Pcb.DirectoryTableBase` for the protected process. When Windows later loads that value into CR3 during a context switch, the processor raises [`#GP(0)`](https://wiki.osdev.org/Exceptions#General_Protection_Fault). EasyAntiCheat's exception handler checks whether the fault came from the expected CR3 load. If it did, the handler rebuilds the real directory-table base, writes it to CR3, and resumes after the faulting instruction.

## The Stored Directory-Table Base Is a Trigger

This is easy to test because a real directory-table base should translate the game's image base, but in the captured run the process object stores 0x4000000853DFF000, and translating the image base through that value returns zero. The CR3 active in the game context is 0x197198000, and it translates the same virtual address to 0x199CFE000.

That mismatch matters for two reasons: bit 62 is set in the stored value, which is why loading it into CR3 raises `#GP(0)`. The low page-frame portion is also different from the active CR3, so the stored value with bit 62 cleared is still not the real directory-table base. It is a trigger, not the value Windows ultimately runs with.

This is the check that produced those values:

```lua
local RustProcess = dbk_getPEProcess( RustPid );

local RustSectionBaseAddress = readQword( RustProcess + 0x520 );
local RustStoredDirectoryTableBase = readQword( RustProcess + 0x28 );
local RustActiveCr3 = dbk_getCR3( );

printf( "RustSectionBaseAddress -> %X", RustSectionBaseAddress );
printf( "RustStoredDirectoryTableBase -> %X", RustStoredDirectoryTableBase );
printf( "RustActiveCr3 -> %X", RustActiveCr3 );

local RustPhysicalFromStored = getPhysicalAddressCR3( RustStoredDirectoryTableBase, RustSectionBaseAddress );
if not RustPhysicalFromStored then
  	print( "RustPhysicalFromStored -> 0" );
else
   	printf( "RustPhysicalFromStored -> %X", RustPhysicalFromStored );
end

local RustPhysicalFromActive = getPhysicalAddressCR3( RustActiveCr3, RustSectionBaseAddress );
if not RustPhysicalFromActive then
  	print( "RustPhysicalFromActive -> 0" );
else
   	printf( "RustPhysicalFromActive -> %X", RustPhysicalFromActive );
end
```

## Why the Stored Value Raises an Exception

The relevant exception comes from the [MOV-to-control-register](https://www.felixcloutier.com/x86/mov-1) rules. Intel describes reserved-bit handling for [CR0](https://en.wikipedia.org/wiki/Control_register#CR0), CR3, and [CR4](https://en.wikipedia.org/wiki/Control_register#CR4) in the same instruction entry, and the CR3 case is the one EasyAntiCheat relies on here:

> "When PCIDs are not enabled, bits 2:0 and bits 11:5 of CR3 are not used and attempts to set them are ignored. **Attempting to set any reserved bits in CR3[63:MAXPHYADDR] results in #GP(0).** Attempting to set any reserved bits in CR4 results in #GP(0)."

The stored value has bit 62 set, and on this machine that bit lands in the reserved portion of CR3, so the processor raises `#GP(0)` when Windows tries to load the stored value. The exact invalid bit is configuration-dependent; a different physical-address width or enabled CPU feature can change which CR3 bits are legal. What matters here is that EasyAntiCheat stores a value that is invalid for this system and uses the resulting exception as the trigger.

## Tracing the Real CR3 Write

The next step is to find the code that takes over after the bad CR3 load. A small [VT-x](<https://en.wikipedia.org/wiki/X86_virtualization#Intel_virtualization_(VT-x)>) hypervisor is good for that because it can log two important events: attempted CR3 writes with illegal bits set, and the next valid CR3 write that follows each fault.

The kernel first tries to load the invalid value from the process object, and immediately afterward EasyAntiCheat writes a valid CR3 value from the same [RVA](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#general-concepts) inside its driver. That RVA identifies the exception-handler path that repairs the load.

The trace below shows the sequence for both the normal context-switch path and `KiAttachProcess`:

```json
{"Type":"Invalid","RVA":"ntoskrnl.exe+0x40028F"} <-- SwapContext
{"Type":"Valid","RVA":"EasyAntiCheat_EOS.sys+0x19A20"}

{"Type":"Invalid","RVA":"ntoskrnl.exe+0x20C130"} <-- KiAttachProcess
{"Type":"Valid","RVA":"EasyAntiCheat_EOS.sys+0x19A20"}
```

## Reversing the Exception Handler

With the CR3 write traced back to EasyAntiCheat, only a small part of the handler matters for this fault. The relevant branch filters for [`STATUS_PRIVILEGED_INSTRUCTION`](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55) and checks whether the faulting instruction starts with `0F 22`, the MOV-to-control-register encoding used by MOV to CR3.

The [ModR/M byte](https://wiki.osdev.org/X86-64_Instruction_Encoding#ModR.2FM_and_SIB_bytes) identifies which general-purpose register supplied the attempted CR3 value. The handler reads that register from the trap frame, resolves EasyAntiCheat's internal state allocation, and uses that state to decide whether the exception belongs to the protected game. That state contains the protected process pointer, the encoded CR3 value, and the key used by this build's reconstruction routine.

If the current process is not the protected game, the handler only accepts a narrow case where the attempted CR3 value matches EasyAntiCheat's stored value. Otherwise, it declines the exception and lets normal exception processing continue.

For the protected game process, the handler also checks that the fault came from EasyAntiCheat's allowed kernel range. When that check passes, it clears the invalid CR3 bits, reconstructs the real page-frame portion with its key, writes the repaired value to CR3, advances RIP by three bytes, and returns success. Advancing RIP skips the original MOV to CR3 because the handler has already performed the corrected load.

The cleaned-up handler looks like this:

```cpp
BOOLEAN EacHooks::HandleException( ExceptionData* Exception, PCONTEXT Context )
{
#define GetFixedCr3( Key ) ((__ROR8__(_byteswap_uint64(Key), 31) & 0xFFFFFFFFF) << 12)

	if ( Exception->Code == STATUS_PRIVILEGED_INSTRUCTION  )
	{
		//
		// --> "mov cr3", ??
		//
		if ( *( WORD* )Context->Rip == 0x220F )
		{
			//
			// mov cr3, "??" <--
			//
			BYTE Operand = *( BYTE* )( Context->Rip + 2 );

			//
			// Convert the operand to an offset in the context structure, starting at RAX.
			//
			Operand &= 7;

			//
			// Retrieve the CR3 value that the faulting instruction attempted to write.
			//
			UINT64* Registers = &Context->Rax;
			UINT64 AttemptedCr3 = Registers[ Operand ];

			//
			// This always resolves to the base of the structure allocation.
			//
			UINT64 DataOffset = InterlockedExchangeAdd64( EAC::InitialDataOffset, 0x1000000000 );
			DataOffset += 0x1000000000;
			DataOffset &= 0xFFFFFFFFF;
			DataOffset <<= 12;

			//
			// The real code uses a stack address in this calculation.
			//
			EAC::EacData* Data = ( EAC::EacData* )( ( 0xFFFFull << 48 ) + DataOffset );

			//
			// Retrieve the current process.
			//
			PEPROCESS CurrentProcess = *( PEPROCESS* )( UINT64( KeGetCurrentThread( ) ) + EAC::ProcessOffset );

			//
			// Simplified for clarity.
			//
			if ( CurrentProcess != Data->Process )
			{
				if ( AttemptedCr3 != Data->Cr3 )
				{
					InterlockedIncrement( Data->Counter );
					return FALSE;
				}

				__writecr3( __readcr3( ) );
				Context->Rip += 3;

				InterlockedIncrement( Data->Counter );
				return TRUE;
			}

			if ( Context->Rip >= EAC::WhitelistStart && Context->Rip < EAC::WhitelistEnd )
			{
				//
				// Remove the invalid bits and reconstruct the CR3 value.
				// The reconstruction expression changes per update.
				//
				UINT64 FixedCr3 = AttemptedCr3 & 0xBFFF000000000FFF;
				FixedCr3 |= GetFixedCr3( Data->Key );

				__writecr3( FixedCr3 );
				Context->Rip += 3;

				InterlockedIncrement( Data->Counter );
				return TRUE;
			}
		}
	}

	return FALSE;
}
```

The script below recreates the same state-lookup logic outside the handler and reads the protected process pointer from the recovered allocation:

```lua
local InitialDataOffset = readQword( EacBase + EacInitialDataOffset );
local DataOffset = bAnd( InitialDataOffset, 0xFFFFFFFFF );
DataOffset = bShl( DataOffset, 12 );

local Data = bOr( bShl( 0xFFFF, 48 ), DataOffset );
if ( readQword( Data + 0xC ) == dbk_getPEProcess( RustPid ) ) then
	print( "Valid Structure" );
else
	print( "Invalid Structure" );
end
```

## Reaching the Exception Handler

Finding the handler still leaves one question: how does execution reach it from the interrupt and exception path? Instead of reversing every branch out of interrupt dispatch, the cleaner route is to break on EasyAntiCheat's dispatcher and walk the guest stack.

Walking return addresses from that stack leads back to a HAL timer callback. The callback pointer at `Timer + 0x70` resolves into EasyAntiCheat's dispatcher, and the registered-timer list confirms that the callback pointers land inside EasyAntiCheat's driver. That gives EasyAntiCheat a path from HAL timer dispatch into its exception code, where it can inspect the faulting instruction and repair the CR3 load.

The relevant callback path looks like this:

```cpp
InternalData = HalpTimerGetInternalData( Timer );
Rax = ( *( __int64 ( __fastcall ** )( __int64 ) )( Timer + 0x70 ) )( InternalData );
```

The script below walks the registered timer list and prints each callback target:

```lua
local Timer = readPointer( HalpRegisteredTimers );
while Timer ~= HalpRegisteredTimers do
      printf( "Timer %X points to Function %X", Timer, readPointer( Timer + 0x70 ) );
      Timer = readPointer( Timer );
end
```

## Reconstructing the Real Directory-Table Base

After the handler and state allocation are known, recovering the real directory-table base is just the decode step. The exact expression changes between EasyAntiCheat updates, but the shape stays the same: resolve the state allocation, read the protected process's stored value, mask off the invalid control bits, apply the per-build decode, and use the result as the real CR3 page-frame value.

The recovery code looks like this:

```cpp
//
// The exact expression changes per update.
//
#define DecryptCr3( Cr3 )

//
// The increment is unnecessary.
//
UINT64 DataOffset = ( InitialDataOffset & 0xFFFFFFFFF ) << 12;
UINT64 Data = *( UINT64* )( ( 0xFFFFull << 48 ) + DataOffset );
DbgPrint( "[Eac] Data -> %llx\n", Data );

PEPROCESS RustProcess;
PsLookupProcessByProcessId( RustPid, &RustProcess );

UINT64 FakeCr3 = *( UINT64* )( UINT64( RustProcess ) + 0x28 );
UINT64 FixedCr3 = DecryptCr3( FakeCr3 & 0xBFFF000000000FFF );
DbgPrint( "[Eac] FixedCr3 -> %llx\n", FixedCr3 );

//
// Dereference the process object to avoid leaking the reference.
//
ObDereferenceObject( RustProcess );
```

## References

- [Intel® 64 and IA-32 Architectures Software Developer's Manual](https://cdrdv2.intel.com/v1/dl/getContent/671200), Volume 2B, "MOV, Move to/from Control Registers."
