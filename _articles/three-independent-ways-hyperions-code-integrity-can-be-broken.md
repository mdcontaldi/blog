---
title: "Three Independent Ways Hyperion's Code Integrity Can Be Broken"
date: 2024-09-02
excerpt: "This article looks at three patched Hyperion code-integrity bypasses: returning a cached clean BLAKE3 digest, hashing a clean clone of the code section, and replacing the heap copy of the reference hash."
tags:
  - roblox
  - hyperion
  - anti-tamper
  - blake3
  - code-integrity
  - integrity-bypass
  - heap-manipulation
  - memory-cloning
  - reverse-engineering
  - user-mode
---

## Disclaimer

This research is published for educational and defensive reverse engineering. It documents Hyperion's code-integrity behavior so analysts can understand the Windows internals involved and recognize the behavior during analysis.

It is not intended to help bypass anti-cheat enforcement, hide unauthorized software, or interfere with any game, player, publisher, or service.

All three methods described here were reported to Roblox through HackerOne and have been patched.

Requests from Roblox, an authorized Hyperion representative, or an appropriate rights holder for correction, revision, or removal will be reviewed, and the article can be changed or taken down if appropriate.

## What Hyperion Compares

Hyperion is Roblox's user-mode anti-tamper system. For code-integrity checks, it hashes selected code pages with [BLAKE3](https://github.com/BLAKE3-team/BLAKE3) and compares the result with a stored reference hash. If the page bytes match the reference, the check passes. If they do not, Hyperion can report an integrity violation.

## Precomputed Hash Substitution

The first method saves clean digests before patching code. It calls Hyperion's internal `GetEarlyDigests` routine for each page in the code section and stores the result by page frame number. Later, the verifier receives the saved digest instead of a digest calculated from the current page bytes:

```cpp
const auto GetEarlyDigests = (std::uint64_t(*)(std::uintptr_t, std::size_t,
    const std::uint32_t*, std::uint64_t, std::uint64_t, void*))(Hyperion + 0x1C29060);

// Precompute hashes before modification.
if constexpr (Method == 1)
{
	for (auto Page = CodeStart; Page < CodeStart + CodeSize; Page += PAGE_SIZE)
	{
		const auto Rva = Page - CodeStart;
		GetEarlyDigests(Page, PAGE_SIZE, iv, 0, CMP_MASK, &EarlyDigests[PFN(Rva)]);
	}
}

// Overwrite with breakpoint to capture execution.
*(std::uint8_t*)GetEarlyDigests = 0xCC;
```

After the clean digests are captured, `GetEarlyDigests` is replaced with a breakpoint. Each later call reaches the exception handler instead of the original routine, which writes the cached digest into the caller-provided output buffer. The verifier still receives a digest in the expected location, but it is from the clean page, not from the patched page:

```cpp
if (Context->Rip == (std::uintptr_t)GetEarlyDigests)
{
	const auto EarlyDigest = *(void**)(Context->Rsp + 0x30);
	std::memcpy(EarlyDigest, &EarlyDigests[PFN(Rva)], sizeof(Digest));
}
```

## Memory Cloning

The second method keeps a complete, unmodified clone of the code section. Verification reads from the clone, while execution continues from the modified live code.

At initialization, the method allocates memory for the clone with [`VirtualAlloc`](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc) and copies the original code section into it:

```cpp
CodeClone = VirtualAlloc(nullptr, CodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
if (!CodeClone)
	return;

std::memcpy(CodeClone, (void*)CodeStart, CodeSize);
```

When Hyperion calls `GetEarlyDigests`, the exception handler redirects the first argument to the matching offset inside the clean clone:

```cpp
else if constexpr (Method == 2)
	Context->Rcx = (std::uintptr_t)CodeClone + Rva;
```

The hash routine reads unchanged bytes, while the process executes modified bytes at the original address. Verification passes because the measured bytes still match the stored reference hash. The cost is one extra copy of the code section, being about 13 MB in this build.

## Direct Heap Replacement of Reference Hashes

The third method changes the stored reference hash directly. In the current version, the linked list that points to each allocation is encrypted, but the hash values themselves are raw heap data. The code finds the old page hash in the process heap and replaces it with the hash of the patched page.

```cpp
template <class T>
void PatchCode(const std::uintptr_t Address, const T& Value)
{
	// This PoC does not support patches that exceed a page boundary.
	if (PAGE_ALIGN(Address) != PAGE_ALIGN(Address + sizeof(T)))
		return;

	const auto HashBlock = [](const void* Data, const std::size_t Size, std::uint8_t* Hash)
	{
		blake3 Hasher;
		blake3_init(&Hasher);

		blake3_update(&Hasher, Data, Size);
		blake3_out(&Hasher, Hash, 32);
	};

	std::uint8_t OriginalHash[32];
	HashBlock((const void*)PAGE_ALIGN(Address), PAGE_SIZE, OriginalHash);

	std::memcpy((void*)Address, &Value, sizeof(T));

	std::uint8_t NewHash[32];
	HashBlock((const void*)PAGE_ALIGN(Address), PAGE_SIZE, NewHash);

	PROCESS_HEAP_ENTRY Entry;
	Entry.lpData = nullptr;

	// While the list pointing to each hash allocation is encrypted, each hash is not.
	// This allows simply iterating over the heap, finding the hash, and replacing it.
	while (HeapWalk(GetProcessHeap(), &Entry))
	{
		if (Entry.wFlags & PROCESS_HEAP_ENTRY_BUSY)
		{
			if (!Entry.lpData)
				continue;

			if (std::memcmp(Entry.lpData, OriginalHash, sizeof(OriginalHash)) == 0)
				std::memcpy(Entry.lpData, NewHash, sizeof(NewHash));
		}
	}
}
```

The order matters. The function hashes the original page, applies the patch, hashes the modified page, then walks the process heap with [`HeapWalk`](https://learn.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapwalk), replacing any busy heap entry that matches the old digest. The integrity check still runs its normal comparison, but the modified page now matches the modified reference hash, so the check passes without changing the verification routine or its call path.

## Validation

To test the bypasses, the selected patch places a mid-function breakpoint in Hyperion's packet-encryption routine:

```cpp
const auto EncryptPacket = Hyperion + 0x12336B0;
*(std::uint8_t*)EncryptPacket = 0xCC;
```

The exception handler emulates the overwritten instruction, advances RIP, and logs the violation count:

```cpp
else if (Context->Rip == EncryptPacket)
{
	// XOR RAX, [R12+0x20]
	Context->Rip += 5;
	Context->Rax ^= *(std::uint64_t*)(Context->R12 + 0x20);

	Utils::Logger::Log("Time: %x", *(std::uint64_t*)(Context->R12 + 0x20));
	Utils::Logger::Log("Violations: %x", *(std::uint32_t*)(Context->R12 + 0x34));

	return EXCEPTION_CONTINUE_EXECUTION;
}
```
