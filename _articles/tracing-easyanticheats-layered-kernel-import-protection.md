---
title: "Tracing EasyAntiCheat's Layered Kernel Import Protection"
date: 2023-07-24
excerpt: "This article follows EasyAntiCheat's protected kernel imports from SHA1 export-name matching to the encrypted values stored in .data, then uses hypervisor traps to recover the per-call-site keys and temporary import metadata."
tags:
  - easyanticheat
  - reverse-engineering
  - kernel-driver
  - import-resolution
  - virtualization-based-obfuscation
  - asymmetric-key-transform
  - sha1
  - ept
  - hypervisor-instrumentation
  - windows-kernel
  - anti-cheat
---

## Disclaimer

This research is published for educational and defensive reverse engineering. It documents EasyAntiCheat's protected kernel import-resolution path so analysts can understand the Windows internals involved and recognize the behavior during analysis.

It is not intended to help bypass anti-cheat enforcement, hide unauthorized software, or interfere with any game, player, publisher, or service.

Requests from Epic Games, an authorized EasyAntiCheat representative, or an appropriate rights holder for correction, revision, or removal will be reviewed, and the article can be changed or taken down if appropriate.

## How Riot Vanguard Handles Manual Imports

Riot Vanguard shows the simple form of manual import resolution. Instead of leaving a normal import-table entry, the driver stores the export name encrypted, decrypts it on the stack, and passes the plaintext name to an internal function:

```cpp
void* VgkExports::ExEnumHandleTable(void* a1)
{
  v17.m128i_i64[1] = 0x3DC8C9558A64BA8Ai64;
  v18.m128i_i64[0] = 0xD6EBDD7A0CEE792Bui64;
  v19.m128i_i64[1] = 0x3DC8C9558A64BA8Ai64;
  v18.m128i_i64[1] = 0xD6C6BCCF590828A8ui64;
  v1 = _mm_load_si128(&v18);
  v19.m128i_i64[0] = 0xC7884760EDC680EDui64;
  v16.m128i_i64[0] = 0xB7A3B00F62AB016Eui64;
  v16.m128i_i64[1] = 0xBAA4DD9B3C644CC6ui64;
  v17.m128i_i64[0] = 0xC7884760EDC68088ui64;
  v2 = *(__int64 **)a1;
  v17 = _mm_xor_si128(v17, v19);
  v16 = _mm_xor_si128(v1, v16);
  Export = FindExport(*v2, v16.m128i_i8, 0i64, 0i64);
  /* redacted code */
  return Export;
}
```

[Lazy Importer](https://github.com/justasmasiulis/lazy_importer) avoids that plaintext-name step by hashing import names instead of reconstructing them before lookup.

## The Per-Call-Site Transform

EasyAntiCheat's protected imports add another step at the call site. The shared helper produces an intermediate value, then the caller rotates that value and applies XOR before making the call:

```cpp
v16 = DecryptImport(qword_125B00);
((void (__fastcall *)(__int64))(__ROL8__(v16, 29) ^ 0x3A505A07B9BA3B9Ei64))(v15);
```

Because the rotate count and XOR key are part of the call site, and the caller can be inside EasyAntiCheat's code obfuscation, hooking the shared helper only gives the value that is about to be transformed, not the final function address.

The final transform can be recovered statically by lifting and deobfuscating the call site, but the easier route is dynamic: capture execution after the helper returns, emulate the remaining caller-side operations, and stop when the final target address appears.

## The Asymmetric Encryption Layer

Under the per-call-site layer is the shared decryption routine. It reads two stored values, decrypts the low and high halves separately, and joins them into a 64-bit result:

```cpp
uint64_t DecryptImport( uint64_t* PublicKeys )
{
    uint64_t First  = DecryptFirst( PublicKeys[ 0 ] );
    uint64_t Second = DecryptSecond( PublicKeys[ 1 ] ) << 32;

    return First | Second;
}
```

The initialization side uses the inverse encryptor to produce the stored values:

```cpp
__int64 __fastcall sub_6F4E4(unsigned __int64 a1, unsigned __int64 a2, unsigned int a3)
{
  unsigned __int64 v3; // r9
  __int64 i; // r8

  v3 = a3;
  for ( i = 1i64; a1; v3 = v3 * (unsigned __int128)v3 % a2 )
  {
    if ( (a1 & 1) != 0 )
      i = (unsigned __int64)i * (unsigned __int128)v3 % a2;
    a1 >>= 1;
  }
  return i;
}
```

A breakpoint on that routine shows the same RCX and RDX key pairs recurring while R8 carries each value being encrypted:

```json
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0xA588E17A" }
{ "Rcx":"0x1D34200DE5B033A1", "Rdx":"0x237626ED2C9C28F3", "R8":"0x20FAECB8" }
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0x63558ACF" }
{ "Rcx":"0x1D34200DE5B033A1", "Rdx":"0x237626ED2C9C28F3", "R8":"0xAD8C5A8"  }
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0x30696C03" }
{ "Rcx":"0x1D34200DE5B033A1", "Rdx":"0x237626ED2C9C28F3", "R8":"0x46D4F31E" }
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0xCFBFE39F" }
{ "Rcx":"0x1D34200DE5B033A1", "Rdx":"0x237626ED2C9C28F3", "R8":"0xBB301A01" }
{ "Rcx":"0x35375306D545459",  "Rdx":"0x12D8ED6858CD15B7", "R8":"0xD4D49738" }
```

During initialization, EasyAntiCheat resolves the address of the target export, applies the inverse of the call-site transform, encrypts the result, and stores the two values in the .data section. The private key is only needed during initialization and is discarded before normal runtime use.

Patching one of those stored values as if it were a function pointer would not produce a valid call target. The values feed `DecryptImport`, and even after decryption, the caller still has to apply its own transform before the value becomes callable.

## Catching the Public-Key Writes

To catch the stored values as they are created, an [EPT](https://en.wikipedia.org/wiki/Second_Level_Address_Translation#Intel%27s_Extended_Page_Tables) write trap is placed on the .data values for a known protected import:

```cpp
AddEptHook_Range( EacBase + 0x125B00, EacBase + 0x125B08, HvDebugger::HvAccess::Write,
    +[ ]( HvDebugger::HvContext* Context, uint64_t Address, uint64_t& Pfn )
{
    WriteLog( "WriteTrap", TraceLoggingHexUInt64( EAC_BASE( Context->Rip ), "RipRva" ), TraceLoggingHexUInt64( EAC_BASE( Address ), "AddrRva" ) );

    return false;
} );
```

The write trap records the writer RIP and the address being written:

```json
{ "RipRva":"0x91FB7E", "AddrRva":"0x125B00" }
{ "RipRva":"0xD1C721", "AddrRva":"0x125B08" }
```

Two writes happen before that import is resolved, so they are left out. The two writes shown above create the stored values for the protected import. Both writer RVAs land inside virtualized code, so RIP alone does not identify the import-initialization logic above the VM handler.

## Following the Stack from the Write Handler

Because the writes come from virtualized code, the writer RIP only identifies the handler responsible for the store, not the logic that led there. Dumping return addresses from the current stack can expose the native caller chain behind it:

```cpp
uint64_t* Stack = ( uint64_t* )Context->Rsp;

for ( size_t Idx = 0; Idx < 200; Idx++ )
{
    uint64_t Value = Stack[ Idx ];
    if ( Value && IN_EAC( Value ) )
        WriteLog( "StackDump", TraceLoggingHexUInt64( Idx ), TraceLoggingHexUInt64( EAC_BASE( Value ), "Rva" ) );
}
```

The raw stack dump contains duplicates, the trap address, and entries from driver initialization:

```json
{ "Idx":"0x0",  "Rva":"0x125B00" } <-- Trap Location
{ "Idx":"0x23", "Rva":"0x6F4E4"  }
{ "Idx":"0x24", "Rva":"0x6F4E4"  }
{ "Idx":"0x25", "Rva":"0x6F598"  }
{ "Idx":"0x4B", "Rva":"0x66698C" }
{ "Idx":"0x4D", "Rva":"0x125B00" } <-- Trap Location
{ "Idx":"0x52", "Rva":"0x18F9E4" } <-- DriverEntry
{ "Idx":"0x63", "Rva":"0x18FAC0" }
{ "Idx":"0x65", "Rva":"0x18FA80" }
{ "Idx":"0x6D", "Rva":"0x74F8E2" }
```

After removing duplicates, the trap address, and everything after `DriverEntry` at 0x18F9E4, three RVAs remain. They point to the inverse encryptor, a setup function that carries 0x1861D0 in RCX, and an unrelated utility:

```json
{ "Idx":"0x23", "Rva":"0x6F4E4"  }
{ "Idx":"0x25", "Rva":"0x6F598"  }
{ "Idx":"0x4B", "Rva":"0x66698C" }
```

## The SHA1 Export Matcher

The next piece is export-name matching. Since `NtGlobalFlag` is the target export name for one protected import, the trace places a read trap on that name:

```cpp
AddEptHook( Utils::GetExportName( "NtGlobalFlag" ), HvDebugger::HvAccess::Read,
    +[ ]( HvDebugger::HvContext* Context, uint64_t Address, uint64_t& Pfn )
{
    WriteLog( "ReadTrap", TraceLoggingHexUInt64( EAC_BASE( Context->Rip ), "Rva" ) );

    uint64_t* Stack = ( uint64_t* )Context->Rsp;

    for ( size_t Idx = 0; Idx < 200; Idx++ )
    {
        uint64_t Value = Stack[ Idx ];
        if ( Value && IN_EAC( Value ) )
            WriteLog( "StackDump", TraceLoggingHexUInt64( Idx ), TraceLoggingHexUInt64( EAC_BASE( Value ), "Rva" ) );
    }

    return false;
} );
```

The trap shows the export-name reader, the SHA1 routine, and the same initialization addresses on the stack:

```json
{ "Rva":"0x2FE234"               } <-- Read Handler
{ "Rva":"0x4637B"                } <-- SHA1 Read
{ "Idx":"0xF",  "Rva":"0x6B09A5" } <-- SHA1 Caller
{ "Idx":"0x13", "Rva":"0x463AC"  } <-- SHA1 Function
{ "Idx":"0x1E", "Rva":"0x125600" } <-- Export Keys
{ "Idx":"0x1F", "Rva":"0x6F584"  } <-- Placeholder Function
{ "Idx":"0x3A", "Rva":"0x1861D0" } <-- Chunk in .data
{ "Idx":"0x3D", "Rva":"0x924C56" }
{ "Idx":"0x67", "Rva":"0x66698C" } <-- Useless Function
{ "Idx":"0x69", "Rva":"0x1260F8" } <-- Random Export
{ "Idx":"0x6E", "Rva":"0x18F9E4" } <-- DriverEntry
{ "Idx":"0x7F", "Rva":"0x18FAC0" }
{ "Idx":"0x81", "Rva":"0x18FA80" }
{ "Idx":"0x89", "Rva":"0x74F8E2" }
```

The routine at 0x463AC matches SHA1 based on the constants in the context: 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, and 0xCA62C1D6.

The handler at 0x2FE234 reads the export name byte by byte and passes the resulting length into the SHA1 routine, matching a virtualized inline `strlen` feeding the hash.

After the known entries are accounted for, 0x924C56 is the remaining code address. The same .data address, 0x1861D0, appears again, tying the export matcher back to the earlier public-key writes.

## Finding Where Imports Are Initialized

The 0x924C56 return address points back to a VMCALL handler. Hooking the handler and logging the callee gives:

```cpp
AddEptHook( EacBase + 0x924C52, HvDebugger::HvAccess::Execute,
    +[ ]( HvDebugger::HvContext* Context, uint64_t Address, uint64_t& Pfn )
{
    /*
      seg007:0000000000924C4B add rsp, 110h
      seg007:0000000000924C52 call qword ptr [rsp+8]
      seg007:0000000000924C56 sub rsp, 110h
    */
    uint64_t Function = *( uint64_t* )( Context->Rsp + 8 );
    WriteLog( "Vmcall", TraceLoggingHexUInt64( EAC_BASE( Function ), "Function" ) );

    HvDebugger::DumpRegisters( Context );

    return false;
} );
```

Here are the results:

```json
{ "Function":"0x72E98"                       }
{ "Name":"RCX", "Value":"0xFFFF8E8BAE7255E0" }
{ "Name":"RDX", "Value":"0xFFFFF80706E00000" }
{ "Name":"R8",  "Value":"0xFFFF8E8BAE7256C0" }
```

The native target at 0x72E98 is the import initializer. The virtualized code calls it once for each module whose exports are used to satisfy protected imports. In this log, RDX is the base address of ntoskrnl.exe.

The recovered parameters identify the destination and the module being searched, but not the list of imports to resolve. That missing input points back to 0x1861D0:

- RCX points to the two public-key values.
- RDX holds the target module base address.
- R8 points to a resolved-import counter, confirmed by observing it increment after each resolution.

## Recovering the Import Metadata

At this point, 0x1861D0 has appeared in the write-handler stack, the export-name read stack, and the initializer. A read trap on that address shows who consumes it:

```cpp
AddEptHook( EacBase + 0x1861D0, HvDebugger::HvAccess::Read,
    +[ ]( HvDebugger::HvContext* Context, uint64_t Address, uint64_t& Pfn )
{
    WriteLog( "ReadTrap", TraceLoggingString( Symbolize( Context->Rip ), "Name" ) );

    return false;
} );
```

The log starts in the sorting code and then reaches the read handlers that use the same address:

```json
{ "Name":"EasyAntiCheat_EOS.sys+0x73228"  } <-- Sorting Function
{ "Name":"ntoskrnl.exe+0x3D0A9A"          } <-- qsort
{ "Name":"ntoskrnl.exe+0x3D0AD3"          } <-- qsort
{ "Name":"EasyAntiCheat_EOS.sys+0x7322B"  } <-- Sorting Function
{ "Name":"ntoskrnl.exe+0x3D0A23"          } <-- qsort
{ "Name":"EasyAntiCheat_EOS.sys+0x21F118" } <-- Reading Handler
{ "Name":"EasyAntiCheat_EOS.sys+0x855527" } <-- Reading Handler
{ "Name":"EasyAntiCheat_EOS.sys+0x425042" } <-- Reading Handler
{ "Name":"EasyAntiCheat_EOS.sys+0x86D2BC" } <-- Reading Handler
{ "Name":"EasyAntiCheat_EOS.sys+0x425042" } <-- Reading Handler
```

Those ntoskrnl.exe addresses are calls into [`qsort`](https://learn.microsoft.com/en-us/cpp/c-runtime-library/reference/qsort?view=msvc-170). The arguments include the array base, element count, and element size, which is enough to dump the protected-import records before the sort changes the array:

```cpp
AddEptHook( Utils::GetExport( "qsort" ), HvDebugger::HvAccess::Execute,
    +[ ]( HvDebugger::HvContext* Context, uintptr_t Address, uint64_t& Pfn )
{
    uint64_t ReturnAddress = *( uint64_t* )Context->Rsp;
    if ( !IN_EAC( ReturnAddress ) )
      return false;

    Utils::DumpArray( &FormatElements, Context->Gpr->rcx /* Base of Elements */, Context->Gpr->rdx /* Number of Elements */, Context->Gpr->r8 /* Size of Elements */ );

    return false;
} );
```

EasyAntiCheat keeps this metadata at 0x1861D0 during initialization and clears it after encryption completes. The full dump contains more records; the two shown here have a sort key, an inline-transform key, a pointer to the stored values, and a fallback, which matches the decompiled fallback paths:

```json
{ "Sort":"0x6556BC1D6053223C", "InlinedKey":"0x65091738C0592277", "Export":"0x1263E8", "Default":"0x6F584" }
{ "Sort":"0x386399B9B0FD723E", "InlinedKey":"0xF26FB57ABCF6FADF", "Export":"0x126408", "Default":"0x6F584" }
```

That gives the layout:

```cpp
struct ProtectedImportData
{
    uint64_t Sort;
    uint64_t InlinedKey;

    uint64_t* PublicKeys;
    uint64_t Default;
}
```

## Import Dump

```text
[IMPORT] Name: CmRegisterCallback | Xor Key: 0xbb1f64bf9ab87b86 | Rol Key: 0x37
[IMPORT] Name: CmRegisterCallbackEx | Xor Key: 0x612e6560a4ebf5fb | Rol Key: 0x7
[IMPORT] Name: CmUnRegisterCallback | Xor Key: 0x299b589e67c59af1 | Rol Key: 0x39
[IMPORT] Name: DbgSetDebugPrintCallback | Xor Key: 0x6860b4392878dd10 | Rol Key: 0x1b
[IMPORT] Name: ExAcquireFastMutex | Xor Key: 0xada427a364ca8bac | Rol Key: 0x33
[IMPORT] Name: ExAcquireFastMutexUnsafe | Xor Key: 0x42a360075e14cb61 | Rol Key: 0xb
[IMPORT] Name: ExAcquirePushLockExclusiveEx | Xor Key: 0x41faf705a79168e5 | Rol Key: 0x5
[IMPORT] Name: ExAcquirePushLockSharedEx | Xor Key: 0xa12e4f998a51bf09 | Rol Key: 0x7
[IMPORT] Name: ExAcquireResourceExclusiveLite | Xor Key: 0x74ab327a1e3a58a9 | Rol Key: 0xd
[IMPORT] Name: ExAcquireRundownProtection | Xor Key: 0x44653d7356a51eb | Rol Key: 0x5
[IMPORT] Name: ExAcquireSpinLockExclusive | Xor Key: 0xea8535158676f134 | Rol Key: 0x1f
[IMPORT] Name: ExAllocatePoolWithTag | Xor Key: 0x1a523094349d7545 | Rol Key: 0x31
[IMPORT] Name: ExEnumHandleTable | Xor Key: 0x884bac5feacb270f | Rol Key: 0x7
[IMPORT] Name: ExEventObjectType | Xor Key: 0xa36ccb62f1654165 | Rol Key: 0x35
[IMPORT] Name: ExFreePool | Xor Key: 0x2e998999739c9979 | Rol Key: 0x17
[IMPORT] Name: ExGetPreviousMode | Xor Key: 0x68a0d15983e62203 | Rol Key: 0x27
[IMPORT] Name: ExRaiseAccessViolation | Xor Key: 0xe9f99cb409c00923 | Rol Key: 0x3d
[IMPORT] Name: ExRaiseDatatypeMisalignment | Xor Key: 0x99ff5de92152d7c9 | Rol Key: 0x3f
[IMPORT] Name: ExRaiseHardError | Xor Key: 0x3462e2cc97eb7b7b | Rol Key: 0x9
[IMPORT] Name: ExReleaseFastMutex | Xor Key: 0x2cb5c4ca33259bf | Rol Key: 0xf
[IMPORT] Name: ExReleaseFastMutexUnsafe | Xor Key: 0xb1f80bb57f00c109 | Rol Key: 0x19
[IMPORT] Name: ExReleasePushLockEx | Xor Key: 0x1ff3fc9770048d1a | Rol Key: 0x1b
[IMPORT] Name: ExReleaseResourceLite | Xor Key: 0x307c82f4a31b5303 | Rol Key: 0x7
[IMPORT] Name: ExReleaseRundownProtection | Xor Key: 0x522d64855b2d33e4 | Rol Key: 0x3b
[IMPORT] Name: ExReleaseSpinLockExclusive | Xor Key: 0xc6a6320d92752333 | Rol Key: 0x21
[IMPORT] Name: ExUuidCreate | Xor Key: 0x8df1c048d4d5439e | Rol Key: 0x35
[IMPORT] Name: ExfUnblockPushLock | Xor Key: 0xcf890504c0b83beb | Rol Key: 0x1b
[IMPORT] Name: HalAcpiGetTableEx | Xor Key: 0x82aed468742ed17d | Rol Key: 0x17
[IMPORT] Name: HalGetBusDataByOffset | Xor Key: 0x2818b93fd687ef67 | Rol Key: 0x2b
[IMPORT] Name: HalSendNMI | Xor Key: 0x2234badc16adf2a9 | Rol Key: 0x33
[IMPORT] Name: HalSetBusDataByOffset | Xor Key: 0xf17ecf6ff42217b | Rol Key: 0x17
[IMPORT] Name: IoAllocateMdl | Xor Key: 0x94e7be0906d0399c | Rol Key: 0xb
[IMPORT] Name: IoBuildDeviceIoControlRequest | Xor Key: 0xb39f11dc4644d98d | Rol Key: 0x29
[IMPORT] Name: IoCreateDevice | Xor Key: 0xb4f221fd38bed915 | Rol Key: 0x3b
[IMPORT] Name: IoCreateFile | Xor Key: 0xc782ca3f06e62bc2 | Rol Key: 0x3f
[IMPORT] Name: IoCreateSymbolicLink | Xor Key: 0x8e5e8e9d31ed23c3 | Rol Key: 0x1f
[IMPORT] Name: IoDeleteDevice | Xor Key: 0x6ab0b373498fb31d | Rol Key: 0x25
[IMPORT] Name: IoDeleteSymbolicLink | Xor Key: 0x4d27bb36eef9a43f | Rol Key: 0x1f
[IMPORT] Name: IoDeviceObjectType | Xor Key: 0x6633f48fd88c8b51 | Rol Key: 0x2d
[IMPORT] Name: IoDriverObjectType | Xor Key: 0x2fb960f9cd8355d5 | Rol Key: 0x3
[IMPORT] Name: IoEnumerateDeviceObjectList | Xor Key: 0x7fc3175599e2ccb1 | Rol Key: 0xf
[IMPORT] Name: IoFileObjectType | Xor Key: 0xc01ea18376bb1119 | Rol Key: 0x1b
[IMPORT] Name: IoFreeMdl | Xor Key: 0xdf97724a733e1fab | Rol Key: 0x33
[IMPORT] Name: IoGetCurrentProcess | Xor Key: 0xb8da14f81a27a504 | Rol Key: 0x19
[IMPORT] Name: IoGetDeviceAttachmentBaseRef | Xor Key: 0x50671cbf63fb766b | Rol Key: 0x2b
[IMPORT] Name: IoGetDeviceInterfaces | Xor Key: 0xdda42c8c675f29b0 | Rol Key: 0xf
[IMPORT] Name: IoGetDeviceObjectPointer | Xor Key: 0xdcb2df10805dc5ca | Rol Key: 0x1
[IMPORT] Name: IoGetDeviceProperty | Xor Key: 0x138edef6fbfeaba1 | Rol Key: 0x33
[IMPORT] Name: IoGetDevicePropertyData | Xor Key: 0x238694373fc2a3c9 | Rol Key: 0x3f
[IMPORT] Name: IoGetInitialStack | Xor Key: 0x3eec9707dce22df1 | Rol Key: 0x27
[IMPORT] Name: IoGetStackLimits | Xor Key: 0xd23cc15745ec63d0 | Rol Key: 0x3d
[IMPORT] Name: IoGetTopLevelIrp | Xor Key: 0x5390d623b7d032c | Rol Key: 0x23
[IMPORT] Name: IoQueryFileDosDeviceName | Xor Key: 0xd3aea180a446c639 | Rol Key: 0x21
[IMPORT] Name: IoRegisterPlugPlayNotification | Xor Key: 0xe705666aae15c314 | Rol Key: 0x25
[IMPORT] Name: IoThreadToProcess | Xor Key: 0x2cd3f1a96b445353 | Rol Key: 0xd
[IMPORT] Name: IoUnregisterPlugPlayNotificationEx | Xor Key: 0x38bdd71fa64d2d2e | Rol Key: 0x1d
[IMPORT] Name: IoWMIOpenBlock | Xor Key: 0x48f5400f2b454bc0 | Rol Key: 0x3f
[IMPORT] Name: IoWMIQueryAllData | Xor Key: 0xe059459bc5e245a9 | Rol Key: 0x2d
[IMPORT] Name: IofCompleteRequest | Xor Key: 0xdaf3eb336eac875a | Rol Key: 0x2d
[IMPORT] Name: KdAcquireDebuggerLock | Xor Key: 0xb1776365b5cd1673 | Rol Key: 0x29
[IMPORT] Name: KdChangeOption | Xor Key: 0xc63f30c212b581d9 | Rol Key: 0x23
[IMPORT] Name: KdDebuggerEnabled | Xor Key: 0xfb04ddd7b78c2e77 | Rol Key: 0x29
[IMPORT] Name: KdDebuggerNotPresent | Xor Key: 0x121bd746f2740584 | Rol Key: 0x9
[IMPORT] Name: KdDisableDebugger | Xor Key: 0xec72db0cce999704 | Rol Key: 0x27
[IMPORT] Name: KdEnteredDebugger | Xor Key: 0x186cd366d0bec7c3 | Rol Key: 0x3f
[IMPORT] Name: KdReleaseDebuggerLock | Xor Key: 0xd63e1203e9d4977e | Rol Key: 0x29
[IMPORT] Name: KeAcquireQueuedSpinLock | Xor Key: 0x9826288651dfa317 | Rol Key: 0x5
[IMPORT] Name: KeAcquireSpinLockAtDpcLevel | Xor Key: 0x82fd61b31ebc3059 | Rol Key: 0x13
[IMPORT] Name: KeAddProcessorAffinityEx | Xor Key: 0x195c7600e6859f1c | Rol Key: 0x25
[IMPORT] Name: KeAlertThread | Xor Key: 0xe086b763bf360310 | Rol Key: 0x25
[IMPORT] Name: KeAreAllApcsDisabled | Xor Key: 0xdda81ee455fb1f71 | Rol Key: 0x9
[IMPORT] Name: KeBugCheckEx | Xor Key: 0x731a065ca395d057 | Rol Key: 0x13
[IMPORT] Name: KeCapturePersistentThreadState | Xor Key: 0xc4d8e8249edc8f2c | Rol Key: 0x23
[IMPORT] Name: KeClearEvent | Xor Key: 0xe8eaf431f66e50f3 | Rol Key: 0x7
[IMPORT] Name: KeConvertAuxiliaryCounterToPerformanceCounter | Xor Key: 0xf2ba11baf43a13bd | Rol Key: 0x11
[IMPORT] Name: KeDelayExecutionThread | Xor Key: 0xd7af510510d87ab7 | Rol Key: 0x31
[IMPORT] Name: KeDeregisterBugCheckReasonCallback | Xor Key: 0xb9b260f89700a9db | Rol Key: 0x3
[IMPORT] Name: KeDeregisterNmiCallback | Xor Key: 0x3c0ac2e0fa5ad363 | Rol Key: 0x2b
[IMPORT] Name: KeEnterCriticalRegion | Xor Key: 0xe2ce95b1c5638e99 | Rol Key: 0x35
[IMPORT] Name: KeEnterGuardedRegion | Xor Key: 0xf38e09bb443adddd | Rol Key: 0x23
[IMPORT] Name: KeFlushEntireTb | Xor Key: 0xb3d9e2074c257d7b | Rol Key: 0x17
[IMPORT] Name: KeFlushQueuedDpcs | Xor Key: 0x2d3a1a05ba1ab85b | Rol Key: 0x13
[IMPORT] Name: KeGenericCallDpc | Xor Key: 0xb19d65b467e8a529 | Rol Key: 0x3d
[IMPORT] Name: KeGetCurrentProcessorNumberEx | Xor Key: 0x51ebd64afba61625 | Rol Key: 0x23
[IMPORT] Name: KeInitializeAffinityEx | Xor Key: 0x85414b60521f30db | Rol Key: 0x3
[IMPORT] Name: KeInitializeApc | Xor Key: 0x521f375031894566 | Rol Key: 0x15
[IMPORT] Name: KeInitializeDpc | Xor Key: 0x7ecf4a5058f67591 | Rol Key: 0xb
[IMPORT] Name: KeInitializeEvent | Xor Key: 0x5c641cdfbc1c6504 | Rol Key: 0x19
[IMPORT] Name: KeInitializeMutex | Xor Key: 0x909391a1604f9073 | Rol Key: 0x17
[IMPORT] Name: KeInsertQueueApc | Xor Key: 0x4c7f8ebce7bbf9ed | Rol Key: 0x25
[IMPORT] Name: KeInsertQueueDpc | Xor Key: 0x9910ec40eaabe695 | Rol Key: 0x35
[IMPORT] Name: KeIpiGenericCall | Xor Key: 0x15c100c75787e1ad | Rol Key: 0xd
[IMPORT] Name: KeLeaveCriticalRegion | Xor Key: 0x5ff2cd089ec5a3d4 | Rol Key: 0x3d
[IMPORT] Name: KeLeaveGuardedRegion | Xor Key: 0xe1915041bf87aa9d | Rol Key: 0x35
[IMPORT] Name: KeQueryActiveProcessorCountEx | Xor Key: 0xfc113c070bba37ce | Rol Key: 0x3f
[IMPORT] Name: KeQuerySystemTimePrecise | Xor Key: 0x63c02a24d15293ed | Rol Key: 0x3b
[IMPORT] Name: KeQueryTimeIncrement | Xor Key: 0x78048f95794956e | Rol Key: 0x15
[IMPORT] Name: FsRtlNumberOfRunsInBaseMcb | Xor Key: 0xe40356c8d0feca8f | Rol Key: 0x37
[IMPORT] Name: KeRegisterBugCheckReasonCallback | Xor Key: 0x4db38b5fcb7bfd6c | Rol Key: 0x15
[IMPORT] Name: KeRegisterNmiCallback | Xor Key: 0xfba9f4b980ea81c2 | Rol Key: 0x1
[IMPORT] Name: KeReleaseMutex | Xor Key: 0x1b6a2cb22284e397 | Rol Key: 0x15
[IMPORT] Name: KeReleaseQueuedSpinLock | Xor Key: 0x7445df25b1352029 | Rol Key: 0x1d
[IMPORT] Name: KeReleaseSpinLockFromDpcLevel | Xor Key: 0x543a4be9774f66f5 | Rol Key: 0x39
[IMPORT] Name: KeRevertToUserAffinityThreadEx | Xor Key: 0x57e5cade770aa381 | Rol Key: 0x37
[IMPORT] Name: KeSetEvent | Xor Key: 0x4fddc55bff403ba3 | Rol Key: 0x13
[IMPORT] Name: KeSetPriorityThread | Xor Key: 0xd2d737063b4b59c1 | Rol Key: 0x21
[IMPORT] Name: KeSetSystemAffinityThreadEx | Xor Key: 0x9341f300f5064169 | Rol Key: 0x35
[IMPORT] Name: KeSignalCallDpcDone | Xor Key: 0x67019b893b0a6803 | Rol Key: 0x19
[IMPORT] Name: KeSignalCallDpcSynchronize | Xor Key: 0xc742e6b154cb24d9 | Rol Key: 0x3
[IMPORT] Name: KeStackAttachProcess | Xor Key: 0x1b3e8ec9dc5e1be5 | Rol Key: 0x1b
[IMPORT] Name: KeTestAlertThread | Xor Key: 0x8c7904b1b86ddb0f | Rol Key: 0x7
[IMPORT] Name: KeUnstackDetachProcess | Xor Key: 0x51814feff188a9af | Rol Key: 0xd
[IMPORT] Name: KeWaitForMultipleObjects | Xor Key: 0x3569031da82a0d84 | Rol Key: 0x9
[IMPORT] Name: KeWaitForMutexObject | Xor Key: 0x404601820dc7b899 | Rol Key: 0xb
[IMPORT] Name: MmAllocateContiguousNodeMemory | Xor Key: 0xa4dd7d50f5aa5b79 | Rol Key: 0x9
[IMPORT] Name: MmAllocateMappingAddress | Xor Key: 0x330c2d1054e56317 | Rol Key: 0x25
[IMPORT] Name: MmCopyMemory | Xor Key: 0x6198d3bf97f6e99c | Rol Key: 0xb
[IMPORT] Name: MmFreeContiguousMemory | Xor Key: 0x846eeaae20854f03 | Rol Key: 0x27
[IMPORT] Name: MmFreeMappingAddress | Xor Key: 0x4a7f43d6877c9d91 | Rol Key: 0x2b
[IMPORT] Name: MmGetPhysicalAddress | Xor Key: 0x52c3ff7ba8ad1269 | Rol Key: 0x2b
[IMPORT] Name: MmGetPhysicalMemoryRanges | Xor Key: 0xdbf14e2f32076fc0 | Rol Key: 0x3f
[IMPORT] Name: MmGetSystemRoutineAddress | Xor Key: 0x6f87ad019b98667d | Rol Key: 0x29
[IMPORT] Name: MmGetVirtualForPhysical | Xor Key: 0x2ed3d888b5b7e607 | Rol Key: 0x27
[IMPORT] Name: MmHighestUserAddress | Xor Key: 0x552a57dfdee9f51f | Rol Key: 0x1b
[IMPORT] Name: MmIsAddressValid | Xor Key: 0x54df83e2e488cfc8 | Rol Key: 0x3f
[IMPORT] Name: MmLockPagableDataSection | Xor Key: 0x7af5ea10cad3951d | Rol Key: 0x1b
[IMPORT] Name: MmMapIoSpace | Xor Key: 0x111675f89e407526 | Rol Key: 0x1d
[IMPORT] Name: MmMapIoSpaceEx | Xor Key: 0x7a184c8cbcfd855b | Rol Key: 0x13
[IMPORT] Name: MmMapLockedPagesSpecifyCache | Xor Key: 0xc74b7a0291f18201 | Rol Key: 0x27
[IMPORT] Name: MmProbeAndLockPages | Xor Key: 0xbb4ddb26317e33fb | Rol Key: 0x19
[IMPORT] Name: MmSectionObjectType | Xor Key: 0x2e8047d54823ed0c | Rol Key: 0x19
[IMPORT] Name: MmSecureVirtualMemoryEx | Xor Key: 0x8178b5e223ebfb51 | Rol Key: 0xd
[IMPORT] Name: MmSystemRangeStart | Xor Key: 0xc10b33e8bf48ed5c | Rol Key: 0x13
[IMPORT] Name: MmUnlockPagableImageSection | Xor Key: 0x6481c59fc2f7571c | Rol Key: 0x25
[IMPORT] Name: MmUnlockPages | Xor Key: 0xa315f7a48d89e757 | Rol Key: 0xd
[IMPORT] Name: MmUnmapIoSpace | Xor Key: 0x161a315f317b2565 | Rol Key: 0x15
[IMPORT] Name: MmUserProbeAddress | Xor Key: 0x5be3e7727151f413 | Rol Key: 0x1b
[IMPORT] Name: NtAllocateVirtualMemory | Xor Key: 0xe7b85be9504dd932 | Rol Key: 0x1f
[IMPORT] Name: NtClose | Xor Key: 0x22f01029c7fa1e9f | Rol Key: 0x35
[IMPORT] Name: NtCreateEvent | Xor Key: 0xc7a2ce0b2f74735f | Rol Key: 0xd
[IMPORT] Name: NtCreateFile | Xor Key: 0xe39ed679c43029c9 | Rol Key: 0x1
[IMPORT] Name: NtCreateFile | Xor Key: 0x250abb86b045f923 | Rol Key: 0x3d
[IMPORT] Name: NtCreateSection | Xor Key: 0xdf0fae2fb3df1f60 | Rol Key: 0x2b
[IMPORT] Name: NtDeleteFile | Xor Key: 0xdd0213de9cff6b5a | Rol Key: 0x2d
[IMPORT] Name: NtDeviceIoControlFile | Xor Key: 0xb361c47389ed8be9 | Rol Key: 0x3b
[IMPORT] Name: NtDeviceIoControlFile | Xor Key: 0x57906f4684c3133d | Rol Key: 0x1
[IMPORT] Name: NtDuplicateObject | Xor Key: 0xfc31d7373024f379 | Rol Key: 0x29
[IMPORT] Name: NtFreeVirtualMemory | Xor Key: 0x4758e358331003fd | Rol Key: 0x39
[IMPORT] Name: NtFsControlFile | Xor Key: 0xf23e9890fb8f0ef9 | Rol Key: 0x39
[IMPORT] Name: NtGlobalFlag | Xor Key: 0x33e2d8dddfefc3b | Rol Key: 0x1f
[IMPORT] Name: NtMapViewOfSection | Xor Key: 0x1a7703286d4d53a1 | Rol Key: 0x13
[IMPORT] Name: NtOpenFile | Xor Key: 0xbedb0047ac1d066d | Rol Key: 0x2b
[IMPORT] Name: NtQueryDirectoryFile | Xor Key: 0xd7b695eb3154392d | Rol Key: 0x3d
[IMPORT] Name: NtQueryInformationFile | Xor Key: 0x8d78483e7c002417 | Rol Key: 0x1b
[IMPORT] Name: NtQueryInformationProcess | Xor Key: 0x6331651a490d9e0f | Rol Key: 0x27
[IMPORT] Name: NtQueryInformationProcess | Xor Key: 0xab48323d21cb1ffc | Rol Key: 0x39
[IMPORT] Name: NtQueryInformationThread | Xor Key: 0x75e4cf6bed22a779 | Rol Key: 0x29
[IMPORT] Name: NtQueryInformationToken | Xor Key: 0x100ad2ab56b0c364 | Rol Key: 0x2b
[IMPORT] Name: NtQuerySystemInformation | Xor Key: 0xcacf9da7d7e2df3a | Rol Key: 0x21
[IMPORT] Name: NtQuerySystemInformation | Xor Key: 0x9b3bc8537feb92ef | Rol Key: 0x3b
[IMPORT] Name: NtQueryVolumeInformationFile | Xor Key: 0xc0f68a639e6ff941 | Rol Key: 0x11
[IMPORT] Name: NtReadFile | Xor Key: 0x7f3ca64f95660625 | Rol Key: 0x23
[IMPORT] Name: NtSetInformationProcess | Xor Key: 0xb4f868255ee095d0 | Rol Key: 0x3
[IMPORT] Name: NtSetInformationThread | Xor Key: 0x5fbfa18cdf58423d | Rol Key: 0x21
[IMPORT] Name: NtSetInformationVirtualMemory | Xor Key: 0x9ed940c24cdb4109 | Rol Key: 0x19
[IMPORT] Name: NtTraceControl | Xor Key: 0x2d90e81fa2997d71 | Rol Key: 0x17
[IMPORT] Name: NtWaitForSingleObject | Xor Key: 0xb645ea907f69a9c8 | Rol Key: 0x1
[IMPORT] Name: NtWriteFile | Xor Key: 0xa5a565fa90b645f5 | Rol Key: 0x27
[IMPORT] Name: ObCloseHandle | Xor Key: 0xf49eadec0c49997b | Rol Key: 0x17
[IMPORT] Name: ObDereferenceObjectDeferDelete | Xor Key: 0xae2f25c06e18d97 | Rol Key: 0xb
[IMPORT] Name: ObGetObjectType | Xor Key: 0x9bdf06dac7a803ba | Rol Key: 0x31
[IMPORT] Name: ObIsKernelHandle | Xor Key: 0xa3397d560a0f2765 | Rol Key: 0xb
[IMPORT] Name: ObOpenObjectByName | Xor Key: 0x4ac28ece1bf0f118 | Rol Key: 0x1b
[IMPORT] Name: ObOpenObjectByPointer | Xor Key: 0xd38c84dcf1644be2 | Rol Key: 0x3b
[IMPORT] Name: ObQueryNameString | Xor Key: 0x560afe2e4fbe9e73 | Rol Key: 0x29
[IMPORT] Name: ObReferenceObjectByHandle | Xor Key: 0xc1ab9ae51bd84d24 | Rol Key: 0x1d
[IMPORT] Name: ObReferenceObjectByName | Xor Key: 0xce91ad8972363c49 | Rol Key: 0x11
[IMPORT] Name: ObReferenceObjectByPointer | Xor Key: 0xb19c6c668b24c719 | Rol Key: 0x25
[IMPORT] Name: ObRegisterCallbacks | Xor Key: 0xa25580ccdc9e09dd | Rol Key: 0x23
[IMPORT] Name: ObUnRegisterCallbacks | Xor Key: 0x5bc00f7172507d7f | Rol Key: 0x17
[IMPORT] Name: ObDereferenceObject | Xor Key: 0x181d45190d22bfbf | Rol Key: 0x11
[IMPORT] Name: ObfReferenceObject | Xor Key: 0xb67c1893a066ba7d | Rol Key: 0x29
[IMPORT] Name: PsAcquireProcessExitSynchronization | Xor Key: 0x88d1226de40c1396 | Rol Key: 0x35
[IMPORT] Name: PsCreateSystemThread | Xor Key: 0xbd99b2bd26b1655f | Rol Key: 0x33
[IMPORT] Name: IoDeleteController | Xor Key: 0xea4b3be237bcbfea | Rol Key: 0x3b
[IMPORT] Name: PsGetContextThread | Xor Key: 0x47aa364e9f623f31 | Rol Key: 0x1
[IMPORT] Name: PsGetCurrentProcessId | Xor Key: 0xcf9c377b91adbd82 | Rol Key: 0x9
[IMPORT] Name: PsGetCurrentThreadId | Xor Key: 0xe35845f9b4d30b51 | Rol Key: 0x2d
[IMPORT] Name: PsGetCurrentThreadStackBase | Xor Key: 0xe66babe67e3e8263 | Rol Key: 0x2b
[IMPORT] Name: PsGetCurrentThreadStackLimit | Xor Key: 0x168a102c40f88523 | Rol Key: 0x1d
[IMPORT] Name: PsGetCurrentThreadTeb | Xor Key: 0x4ca348cf77277bb1 | Rol Key: 0x31
[IMPORT] Name: PsGetProcessCreateTimeQuadPart | Xor Key: 0x3f38be1db234fc73 | Rol Key: 0x17
[IMPORT] Name: PsGetProcessDebugPort | Xor Key: 0x69f386979eeb814e | Rol Key: 0x11
[IMPORT] Name: PsGetProcessExitProcessCalled | Xor Key: 0xbdca48692ad30ddd | Rol Key: 0x23
[IMPORT] Name: PsGetProcessExitStatus | Xor Key: 0xfc52d8b85c327f32 | Rol Key: 0x21
[IMPORT] Name: PsGetProcessId | Xor Key: 0xb20c19b8532a363d | Rol Key: 0x21
[IMPORT] Name: PsGetProcessImageFileName | Xor Key: 0x57cb700d77bef595 | Rol Key: 0x2b
[IMPORT] Name: PsGetProcessInheritedFromUniqueProcessId | Xor Key: 0xc8b561897fd5a3b7 | Rol Key: 0x31
[IMPORT] Name: PsGetProcessPeb | Xor Key: 0x5efe9e3bb1d0e5e9 | Rol Key: 0x5
[IMPORT] Name: PsGetProcessSectionBaseAddress | Xor Key: 0xca351e31991b5fc5 | Rol Key: 0x1f
[IMPORT] Name: PsGetProcessSessionId | Xor Key: 0x1ac41cb719087b57 | Rol Key: 0x2d
[IMPORT] Name: PsGetProcessWow64Process | Xor Key: 0x6489c125f213bbd9 | Rol Key: 0x1d
[IMPORT] Name: PsGetThreadId | Xor Key: 0xe52c628878453567 | Rol Key: 0x35
[IMPORT] Name: IoThreadToProcess | Xor Key: 0x8e7aebd44895eb58 | Rol Key: 0x2d
[IMPORT] Name: PsGetThreadProcessId | Xor Key: 0x3eabe8090e94a00d | Rol Key: 0x19
[IMPORT] Name: PsGetThreadWin32Thread | Xor Key: 0xfb1c02678bb27f1a | Rol Key: 0x25
[IMPORT] Name: PsInitialSystemProcess | Xor Key: 0x479b1f9b9c973b23 | Rol Key: 0x23
[IMPORT] Name: PsIsProcessBeingDebugged | Xor Key: 0x91b583a6c3ebcf28 | Rol Key: 0x23
[IMPORT] Name: PsIsProtectedProcess | Xor Key: 0x1ff1b4aea3ec9e5 | Rol Key: 0x25
[IMPORT] Name: PsIsProtectedProcessLight | Xor Key: 0x2f05ef02284cab03 | Rol Key: 0x7
[IMPORT] Name: IoIsSystemThread | Xor Key: 0x6668fd51e3cacfdb | Rol Key: 0x1d
[IMPORT] Name: PsIsThreadTerminating | Xor Key: 0x4f42c823aa38e259 | Rol Key: 0x2d
[IMPORT] Name: PsLookupProcessByProcessId | Xor Key: 0xdb6f6ee419b94df7 | Rol Key: 0x7
[IMPORT] Name: PsLookupProcessThreadByCid | Xor Key: 0xb279989d1bb4ce8b | Rol Key: 0x37
[IMPORT] Name: PsLookupThreadByThreadId | Xor Key: 0x7d497649e4dac9df | Rol Key: 0x3
[IMPORT] Name: PsProcessType | Xor Key: 0xfe2361712f63ad44 | Rol Key: 0x11
[IMPORT] Name: PsReferencePrimaryToken | Xor Key: 0x64da423efbbec5bf | Rol Key: 0xf
[IMPORT] Name: PsReferenceProcessFilePointer | Xor Key: 0x540eb381a37dc9eb | Rol Key: 0x25
[IMPORT] Name: PsReleaseProcessExitSynchronization | Xor Key: 0xaa5ccea8e9a72bdf | Rol Key: 0x3d
[IMPORT] Name: PsRemoveCreateThreadNotifyRoutine | Xor Key: 0xad5068ebffb7e50d | Rol Key: 0x39
[IMPORT] Name: PsRemoveLoadImageNotifyRoutine | Xor Key: 0xc9c69a0921666879 | Rol Key: 0x17
[IMPORT] Name: PsResumeProcess | Xor Key: 0x555e71475e35e991 | Rol Key: 0xb
[IMPORT] Name: PsSetCreateProcessNotifyRoutine | Xor Key: 0x954a8b7ee6f16469 | Rol Key: 0x15
[IMPORT] Name: PsSetCreateThreadNotifyRoutine | Xor Key: 0x61e75ef7884b1b1a | Rol Key: 0x25
[IMPORT] Name: PsSetLoadImageNotifyRoutine | Xor Key: 0x439dcfdca2cea161 | Rol Key: 0x15
[IMPORT] Name: PsSetThreadHardErrorsAreDisabled | Xor Key: 0xa8629b204223f309 | Rol Key: 0x27
[IMPORT] Name: PsSuspendProcess | Xor Key: 0x8559c594b0c0a5ef | Rol Key: 0x25
[IMPORT] Name: PsTerminateSystemThread | Xor Key: 0x37f4ac34c7c123 | Rol Key: 0x1d
[IMPORT] Name: PsThreadType | Xor Key: 0xb7e510eb87581d41 | Rol Key: 0x11
[IMPORT] Name: PsWrapApcWow64Thread | Xor Key: 0xcf1de9e5ec29534e | Rol Key: 0x2f
[IMPORT] Name: RtlCaptureContext | Xor Key: 0x9a98284dae3c27c5 | Rol Key: 0x3f
[IMPORT] Name: RtlCompareString | Xor Key: 0xc612027b55484b08 | Rol Key: 0x27
[IMPORT] Name: RtlCompareUnicodeString | Xor Key: 0xcba09e7e4eb6dccf | Rol Key: 0x1
[IMPORT] Name: RtlConvertSidToUnicodeString | Xor Key: 0xa935110004a7139c | Rol Key: 0x35
[IMPORT] Name: RtlCreateUserThread | Xor Key: 0xe3dedb855df0a163 | Rol Key: 0x15
[IMPORT] Name: RtlDecompressBufferEx | Xor Key: 0xa51c24b8e08fdd44 | Rol Key: 0x11
[IMPORT] Name: RtlEqualSid | Xor Key: 0x2fd5ec18cccb7c4 | Rol Key: 0x3f
[IMPORT] Name: RtlEqualUnicodeString | Xor Key: 0x66a9fc9089f9efa9 | Rol Key: 0x13
[IMPORT] Name: RtlGetCompressionWorkSpaceSize | Xor Key: 0x81422c7b46765b27 | Rol Key: 0x3
[IMPORT] Name: RtlInitializeBitMap | Xor Key: 0xb79552699f3d5cd | Rol Key: 0x1
[IMPORT] Name: RtlIntegerToUnicodeString | Xor Key: 0x6a25f809c96d762f | Rol Key: 0x23
[IMPORT] Name: RtlLookupElementGenericTableAvl | Xor Key: 0x45ebc3f5ed3c55fd | Rol Key: 0x27
[IMPORT] Name: RtlLookupFunctionEntry | Xor Key: 0x532800ebe9fa1dd7 | Rol Key: 0x23
[IMPORT] Name: RtlMultiByteToUnicodeN | Xor Key: 0x7e57fe84a6076dfb | Rol Key: 0x7
[IMPORT] Name: RtlPcToFileHeader | Xor Key: 0xeaf7520cb4a76357 | Rol Key: 0x2d
[IMPORT] Name: RtlRandomEx | Xor Key: 0xf0d1393ba791c1ca | Rol Key: 0x1
[IMPORT] Name: RtlTimeToSecondsSince1970 | Xor Key: 0x66a8d94f928593af | Rol Key: 0x13
[IMPORT] Name: RtlTimeToTimeFields | Xor Key: 0xf67fe5481da30774 | Rol Key: 0x29
[IMPORT] Name: RtlUTF8ToUnicodeN | Xor Key: 0x2c5606a1daabd3f1 | Rol Key: 0x39
[IMPORT] Name: RtlUnicodeStringToAnsiString | Xor Key: 0xb388b2315388ce2f | Rol Key: 0x23
[IMPORT] Name: RtlUnicodeToUTF8N | Xor Key: 0x5763f5210190d8dd | Rol Key: 0x3
[IMPORT] Name: RtlVirtualUnwind | Xor Key: 0x8f1434b65d5f298b | Rol Key: 0x29
[IMPORT] Name: SeCaptureSubjectContext | Xor Key: 0x96141f6053df72a7 | Rol Key: 0x33
[IMPORT] Name: SeExports | Xor Key: 0xa2a117938b7b9125 | Rol Key: 0x1d
[IMPORT] Name: SeLockSubjectContext | Xor Key: 0x7cb4df4fe55c1b3b | Rol Key: 0x1
[IMPORT] Name: SeQueryInformationToken | Xor Key: 0x2f29f6aec3f4d199 | Rol Key: 0xb
[IMPORT] Name: SeRegisterImageVerificationCallback | Xor Key: 0xb3a53620fca3313c | Rol Key: 0x1f
[IMPORT] Name: SeReleaseSubjectContext | Xor Key: 0x6a3c2730b4bcd797 | Rol Key: 0x15
[IMPORT] Name: SeTokenObjectType | Xor Key: 0x44e3ea752875ef1b | Rol Key: 0x5
[IMPORT] Name: SeUnlockSubjectContext | Xor Key: 0x5922f5a1b3108a63 | Rol Key: 0x2b
[IMPORT] Name: SeUnregisterImageVerificationCallback | Xor Key: 0xe426dcf7b2b97939 | Rol Key: 0x1f
[IMPORT] Name: ZwAllocateVirtualMemory | Xor Key: 0xe7b85be9504dd932 | Rol Key: 0x1f
[IMPORT] Name: ZwClose | Xor Key: 0x22f01029c7fa1e9f | Rol Key: 0x35
[IMPORT] Name: ZwCreateFile | Xor Key: 0xe39ed679c43029c9 | Rol Key: 0x1
[IMPORT] Name: ZwCreateKey | Xor Key: 0xdc54e9aa37c02704 | Rol Key: 0x27
[IMPORT] Name: ZwCreateSection | Xor Key: 0xdf0fae2fb3df1f60 | Rol Key: 0x2b
[IMPORT] Name: ZwDeleteFile | Xor Key: 0xdd0213de9cff6b5a | Rol Key: 0x2d
[IMPORT] Name: ZwDeleteKey | Xor Key: 0x2cb7c1ebba165ad5 | Rol Key: 0x3d
[IMPORT] Name: ZwDeleteValueKey | Xor Key: 0xc179735aee015d58 | Rol Key: 0x13
[IMPORT] Name: ZwDeviceIoControlFile | Xor Key: 0x57906f4684c3133d | Rol Key: 0x1
[IMPORT] Name: ZwDuplicateObject | Xor Key: 0xfc31d7373024f379 | Rol Key: 0x29
[IMPORT] Name: ZwEnumerateKey | Xor Key: 0x6db00e7cca24d9fe | Rol Key: 0x7
[IMPORT] Name: ZwEnumerateValueKey | Xor Key: 0xf60b22e54557f229 | Rol Key: 0x23
[IMPORT] Name: ZwFlushInstructionCache | Xor Key: 0x8bad623c64bad65f | Rol Key: 0x2d
[IMPORT] Name: ZwFlushKey | Xor Key: 0x966f604e0bfae505 | Rol Key: 0x39
[IMPORT] Name: ZwFlushVirtualMemory | Xor Key: 0x501ea5c47ed2f501 | Rol Key: 0x19
[IMPORT] Name: ZwFreeVirtualMemory | Xor Key: 0x4758e358331003fd | Rol Key: 0x39
[IMPORT] Name: ZwFsControlFile | Xor Key: 0xf23e9890fb8f0ef9 | Rol Key: 0x39
[IMPORT] Name: ZwGetNextProcess | Xor Key: 0xadcf077e131df9e1 | Rol Key: 0x5
[IMPORT] Name: ZwMapViewOfSection | Xor Key: 0x1a7703286d4d53a1 | Rol Key: 0x13
[IMPORT] Name: ZwOpenDirectoryObject | Xor Key: 0xb24871e93e6b18f | Rol Key: 0x9
[IMPORT] Name: ZwOpenFile | Xor Key: 0xbedb0047ac1d066d | Rol Key: 0x2b
[IMPORT] Name: ZwOpenKey | Xor Key: 0xc67684ca47df596f | Rol Key: 0x35
[IMPORT] Name: ZwOpenSection | Xor Key: 0xa1e1c5c0aa3f69b4 | Rol Key: 0xf
[IMPORT] Name: ZwOpenSymbolicLinkObject | Xor Key: 0xb6d0c35d5fc4816c | Rol Key: 0x15
[IMPORT] Name: ZwProtectVirtualMemory | Xor Key: 0xf935d31a776c9105 | Rol Key: 0x39
[IMPORT] Name: ZwQueryDirectoryFile | Xor Key: 0xd7b695eb3154392d | Rol Key: 0x3d
[IMPORT] Name: ZwQueryDirectoryObject | Xor Key: 0x3294651d60c1770b | Rol Key: 0x27
[IMPORT] Name: ZwQueryFullAttributesFile | Xor Key: 0x34dd5d77ff04efe5 | Rol Key: 0x3b
[IMPORT] Name: ZwQueryInformationFile | Xor Key: 0x8d78483e7c002417 | Rol Key: 0x1b
[IMPORT] Name: ZwQueryInformationProcess | Xor Key: 0xab48323d21cb1ffc | Rol Key: 0x39
[IMPORT] Name: ZwQueryInformationThread | Xor Key: 0x75e4cf6bed22a779 | Rol Key: 0x29
[IMPORT] Name: ZwQueryInformationToken | Xor Key: 0x100ad2ab56b0c364 | Rol Key: 0x2b
[IMPORT] Name: ZwQueryKey | Xor Key: 0xe30f0b65a03b3563 | Rol Key: 0x35
[IMPORT] Name: ZwQueryLicenseValue | Xor Key: 0xb7c6f70db9f7d0e7 | Rol Key: 0x5
[IMPORT] Name: ZwQueryObject | Xor Key: 0x5af80f5359a131b3 | Rol Key: 0x2f
[IMPORT] Name: ZwQuerySection | Xor Key: 0xd1299f9129a10728 | Rol Key: 0x23
[IMPORT] Name: ZwQuerySymbolicLinkObject | Xor Key: 0x71a9d283a3e80388 | Rol Key: 0x37
[IMPORT] Name: ZwQuerySystemEnvironmentValueEx | Xor Key: 0x1f78eeb9f9529fd5 | Rol Key: 0x3d
[IMPORT] Name: ZwQuerySystemInformation | Xor Key: 0xcacf9da7d7e2df3a | Rol Key: 0x21
[IMPORT] Name: ZwQueryValueKey | Xor Key: 0xb9eee51b850cb807 | Rol Key: 0x19
[IMPORT] Name: ZwQueryVirtualMemory | Xor Key: 0xd79a49b1360a6667 | Rol Key: 0x2b
[IMPORT] Name: ZwQueryVolumeInformationFile | Xor Key: 0xc0f68a639e6ff941 | Rol Key: 0x11
[IMPORT] Name: ZwReadFile | Xor Key: 0x7f3ca64f95660625 | Rol Key: 0x23
[IMPORT] Name: ZwSetInformationObject | Xor Key: 0x12570daf5803cfb5 | Rol Key: 0x11
[IMPORT] Name: ZwSetInformationProcess | Xor Key: 0xb4f868255ee095d0 | Rol Key: 0x3
[IMPORT] Name: ZwSetInformationThread | Xor Key: 0x5fbfa18cdf58423d | Rol Key: 0x21
[IMPORT] Name: ZwSetInformationVirtualMemory | Xor Key: 0x9ed940c24cdb4109 | Rol Key: 0x19
[IMPORT] Name: ZwSetSystemEnvironmentValueEx | Xor Key: 0x67a290e2358b8c79 | Rol Key: 0x17
[IMPORT] Name: ZwSetValueKey | Xor Key: 0xc90e3f5ddd845c4b | Rol Key: 0x11
[IMPORT] Name: ZwTerminateProcess | Xor Key: 0x26028664a7247e03 | Rol Key: 0x27
[IMPORT] Name: ZwTraceControl | Xor Key: 0x2d90e81fa2997d71 | Rol Key: 0x17
[IMPORT] Name: ZwUnmapViewOfSection | Xor Key: 0xe3cce1c48b2ba0e9 | Rol Key: 0x5
[IMPORT] Name: ZwWaitForSingleObject | Xor Key: 0xb645ea907f69a9c8 | Rol Key: 0x1
[IMPORT] Name: ZwWriteFile | Xor Key: 0xa5a565fa90b645f5 | Rol Key: 0x27
[IMPORT] Name: __C_specific_handler | Xor Key: 0xda6c6cdaefd72b07 | Rol Key: 0x27
[IMPORT] Name: _vsnprintf | Xor Key: 0x2e744e7118203b27 | Rol Key: 0x23
[IMPORT] Name: _vsnwprintf | Xor Key: 0x49c4f60257b02758 | Rol Key: 0x2d
```
