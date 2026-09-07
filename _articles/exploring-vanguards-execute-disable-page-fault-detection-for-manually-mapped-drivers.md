---
title: "Exploring Riot Vanguard's Page-Fault Trap for Manually Mapped Drivers"
date: 2024-09-22
excerpt: "This article looks at one Vanguard check for manually mapped kernel code. It marks watched pages with the XD bit, catches the instruction-fetch #PF via its KiPageFault hook, and copies the page that tried to execute."
tags:
  - vanguard
  - reverse-engineering
  - kernel-mode
  - page-fault
  - execute-disable-bit
  - manually-mapped-drivers
  - kipagefault
  - kernel-patch-protection
  - windows-internals
  - anti-cheat
  - page-table-entries
---

## Disclaimer

This research is published for educational and defensive reverse engineering. It documents Riot Vanguard's page-fault collection behavior so analysts can understand the Windows internals involved and recognize the behavior during analysis.

It is not intended to help bypass anti-cheat enforcement, hide unauthorized software, or interfere with any game, player, publisher, or service.

Requests from Riot Games, an authorized Riot Vanguard representative, or an appropriate rights holder for correction, revision, or removal will be reviewed, and the article can be changed or taken down if appropriate.

## Execute-Disable and Page-Fault Semantics

Only two processor details are needed here: the [XD bit](https://en.wikipedia.org/wiki/NX_bit), a page-table permission bit, and [#PF](https://wiki.osdev.org/Exceptions#Page_Fault), the page-fault exception.

The XD bit lets software keep a page mapped as data while blocking instruction fetches from it:

> "If the execute-disable bit of a memory page is set, that page can be used only as data. An attempt to execute code from a memory page with the execute-disable bit set causes a page-fault exception."

> "Instructions cannot be fetched from a memory page if IA32_EFER.NXE = 1 and the execute-disable bit is set in any of the paging-structure entries used to map the page."

That gives Vanguard a direct way to catch execution from a watched page. The page can stay mapped, but the first attempt to run code from it raises #PF. Intel names that condition:

> "When execute disable bit capability is enabled (IA32_EFER.NXE = 1), conditions for a page fault to occur include the same conditions that apply to an Intel 64 or IA-32 processor without execute disable bit capability plus the following new condition: an instruction fetch to a linear address that translates to physical address in a memory page that has the execute-disable bit set."

After #PF is raised, [CR2](https://wiki.osdev.org/CPU_Registers_x86-64#CR2) gives the faulting linear address. The page-fault error code says whether the access was an instruction fetch:

> "When a page fault occurs, the processor loads the CR2 register with the linear address that generated the exception."

> "I/D = 1: The fault was caused by an instruction fetch."

## Vanguard's Page-Fault Collection Logic

Vanguard uses that fault to capture the page that tried to run. The driver hooks `KiPageFault`, marks selected kernel ranges with the XD bit, and waits. If code runs from one of those ranges, the processor raises #PF before the instruction executes. The handler checks the faulting address, copies the 4 KiB page that contains the instruction stream, and sets a flag saying that a page was captured.

The user-mode Vanguard component is responsible for sending the captured page to the server, and it gets that page from the driver by sending an IOCTL command.

The signature, offset, and record layout are from the version tested here and can change in an update. The code below tests whether manually mapped code is caught on a given system by clearing the completion flag, spinning until the driver writes a page, checking that the buffer is not empty, and saving the captured page to disk.

```cpp
const auto vgk = nt::driver::get("vgk.sys");
if (!vgk)
    return 0ull;

const auto get_illegal_page_fault = utils::scan_signature(vgk->base, vgk->size,
    "\x48\x83\xEC\x28\x45\x33\xC0\x44");

if (!get_illegal_page_fault)
    return 0ull;

const auto relative = nt::intel::get().read<std::int32_t>(get_illegal_page_fault + 0xA);
if (!relative)
    return 0ull;

return get_illegal_page_fault + *relative + 0xE;

struct illegal_page_fault
{
    bool finished;                      // Did the scan finish?
    std::uint8_t _;                     // Padding.
    std::uint8_t page[4096];            // The 4KB page of captured code.
};

// Get the data struct and clear the finished flag to start fresh.
const auto illegal_page_fault = vgk::illegal_page_fault::get<std::uintptr_t>();
if (!nt::intel::get().write(*illegal_page_fault, false))
    return 1;

while (true)
{
    const auto finished = nt::intel::get().read<bool>(*illegal_page_fault);
    if (!finished)
        return 1;

    // Wait until something is captured.
    if (!*finished)
    {
        std::this_thread::sleep_for(1s);
        continue;
    }

    // Retrieve captured page.
    const auto illegal_page_fault = vgk::illegal_page_fault::get();

    // Ensure that Vanguard caught something useful.
    if (!illegal_page_fault || std::all_of(illegal_page_fault->page,
        illegal_page_fault->page + 4096,
        [](const auto byte) { return !byte; }))
        return 1;

    // Save to disk.
    std::ofstream("illegal-page-fault.bin", std::ios::binary)
        .write((char*)illegal_page_fault->page, 4096);

    break;
}
```

## Avoiding Kernel Integrity Checks

Hooking the Windows page-fault path brings [Kernel Patch Protection](https://learn.microsoft.com/en-us/security-updates/securityadvisories/2007/932596) into the picture because Microsoft describes it as a technology in x64-based Windows that helps protect code and critical kernel structures from modification by unknown software or data. Microsoft also documents [`CRITICAL_STRUCTURE_CORRUPTION`](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption) for cases where the kernel detected critical kernel code or data corruption. The documented corruption categories include function modification, interrupt descriptor table modification, loaded module list modification, and page hash mismatch.

Vanguard is modifying the kernel `.text` section, which is integrity checked. If that hook stayed in place during a check, players would eventually hit a bug check. To handle this, Vanguard removes all hooks before Kernel Patch Protection continues.

The stack below is a captured call stack. In this case, the return path goes through Vanguard code and back to an integrity check invoked by one of its DPC workers:

```text
vgk.sys+0x1867BF <-- Return from the unhook routine.
vgk.sys+0x18619C
vgk.sys+0x1884CE
vgk.sys+0x7394C
ExpCenturyDpcRoutine$fin$0+0x26D <-- Return from the KPP context.
```

## Related Research

This is not a Vanguard-only trick. Other public research has used execute-disable faults to observe kernel execution.

[Can Bölük's PatchGuard research](https://blog.can.ac/2024/06/28/pgc-garbage-collecting-patchguard/) has a different goal, but a similar architectural pattern. It flips execute-disable state on selected kernel pages so that later execution produces a fault. The fault becomes a way to identify execution from pages of interest.

## References

* [Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3A: System Programming Guide, Part 1](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf), Section 6.13, "Page-Level Protection and Execute-Disable Bit."
* [Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3A: System Programming Guide, Part 1](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf), Section 6.13.2, "Execute-Disable Page Protection."
* [Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3A: System Programming Guide, Part 1](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf), Section 6.13.4, "Exception Handling."
* [Intel 64 and IA-32 Architectures Software Developer's Manual, Volume 3A: System Programming Guide, Part 1](https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-vol-3a-part-1-manual.pdf), Section 5.7, "Page-Fault Exceptions," and Figure 5-12, "Page-Fault Error Code."
