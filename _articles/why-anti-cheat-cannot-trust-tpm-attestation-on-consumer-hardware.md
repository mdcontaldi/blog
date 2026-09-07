---
title: "Why Anti-Cheat Cannot Trust TPM Attestation on Consumer Hardware"
date: 2025-11-21
excerpt: "TPM attestation gives anti-cheat systems hardware-rooted evidence that software-only clients cannot reproduce. Consumer platforms weaken the identity, measurement, reference-data, and platform-binding assumptions enough that TPM attestation works as telemetry, not standalone enforcement."
tags:
  - tpm
  - anti-cheat
  - attestation
  - endorsement-key
  - endorsement-certificate
  - measured-boot
  - platform-configuration-registers
  - firmware
  - spi-flash
  - reference-integrity-manifest
  - trust-hierarchy
  - ftpm
  - platform-certificate
  - cuckoo-attack
---

## Introduction

Trusted Platform Module (TPM) attestation gives anti-cheat systems a hardware-rooted signal that a software-only client cannot create on its own. The useful property is not that a real TPM behaves differently from an emulator. The useful property is origin. A manufacturer certifies a key that is supposed to live inside a TPM, and that TPM can sign reports over values held in hardware-protected locations.

That model is strong, but it is narrow. TPM attestation can prove that a selected TPM signed selected evidence. It does not automatically prove that the first measurement code is immutable, that the event log maps to known-good firmware, or that the TPM is physically attached to the gaming PC that runs the match.

On managed enterprise hardware, administrators can make those assumptions true. They control firmware versions, certificate roots, platform inventory, and reference measurements. Consumer anti-cheat systems operate in a different environment. They see incomplete certificates, firmware TPM defects, inconsistent firmware configuration, self-signed boot paths, missing Reference Integrity Manifests, and hardware that may not bind the TPM to the platform in a useful way.

The result is that TPM attestation is valuable anti-cheat telemetry, but it is not a standalone trust oracle for consumer hardware.

## What a TPM Attestation Chain Needs

A verifier needs three separate things before TPM attestation has strong meaning.

1. A genuine reporting root. The verifier must know that the signing key is protected by a real TPM.
2. A trustworthy measurement root. The code that creates the first measurements must not be attacker-controlled.
3. Reference data. The verifier must know what the measurements mean for this exact platform state.

The Trusted Computing Group (TCG) definition of a Root of Trust (RoT) is intentionally blunt:

> "A RoT is trusted always to behave in the expected manner."

A Root of Trust is not proven by later measurements. It is assumed because there is no deeper component available to measure it. This matters for anti-cheat because a TPM can protect registers and keys, but it cannot decide whether the first component that feeds it measurements is honest.

The TPM 2.0 model separates the major roots of trust into the Root of Trust for Measurement (RTM), Root of Trust for Reporting (RTR), and Root of Trust for Storage (RTS). The RTM creates measurements. The RTS protects state, including Platform Configuration Registers (PCRs). The RTR reports selected state to a verifier, usually through an Attestation Key (AK).

## Platform Configuration Registers and Event Logs

A Platform Configuration Register (PCR) is not a normal writable variable. It is an accumulator. Outside of platform-specific reset behavior, a PCR changes through Extend. The TPM 2.0 Library, Part 1, describes that update rule this way:

> "only way to change a PCR value is to Extend it."

The Extend operation computes a new value from the old PCR value and a measurement digest. In simplified form, the operation is `PCRnew = Halg(PCRold || digest)`. The result is order-dependent. The same measurements in a different order produce a different PCR value.

The PCR value alone is not a readable boot history. It is the digest of a sequence. The event log supplies that sequence. The TCG PC Client Platform Firmware Profile requires platform firmware to log measurements when the TPM is visible.

A verifier replays the event log, recomputes the PCR values, and compares them with the PCR values signed by the TPM. That check detects an event log that does not match the TPM state. It does not prove that each logged component is good. It only proves that the log and the quoted PCR values are consistent with each other.

## Endorsement Keys, Endorsement Certificates, and Attestation Keys

The Endorsement Key (EK) is the TPM identity root. In TPM 2.0, the EK is a restricted decryption key pair derived from the Endorsement Primary Seed (EPS). By itself, the public EK is only a public key. It becomes meaningful when a trusted entity certifies it. The TPM 2.0 Library, Part 0, describes that dependency this way:

> "Unless the EK is certified by a trusted entity"

TCG terminology uses Endorsement Certificate for the manufacturer certificate over the EK. Microsoft documentation and Windows tooling often use EKCert for the same operational concept.

The Attestation Key (AK) is different. It is the signing key used for attestation data, including `TPM2_Quote` output. A properly created AK has restrictions that prevent a caller from using it as a general-purpose signing key for arbitrary attacker-controlled bytes. The TPM 2.0 Library, Part 1, describes the restriction this way:

> "only sign a digest that has been produced by the TPM."

Credential activation links those pieces. A verifier checks the Endorsement Certificate, encrypts a credential to the EK, binds that credential to the AK, and asks the TPM to recover it through `TPM2_ActivateCredential`. If the TPM returns the expected secret, the verifier has evidence that the AK and EK belong to the same TPM.

That flow proves TPM residency for the AK. It does not prove that the platform is clean. It only establishes a trusted reporting channel into the TPM.

## What Anti-Cheat Actually Wants

A software-only anti-cheat can be copied, patched, or emulated because it runs in an environment the attacker tries to control. A TPM adds one non-software property. A verifier can distinguish a software-generated key from a key certified as TPM-resident.

That property depends on the Endorsement Certificate. If the verifier cannot authenticate the EK, then a software emulator can generate its own EK, create its own AK, complete a self-consistent protocol, and sign fabricated evidence. The transcript may look correct, but it has no manufacturer-backed origin.

Standard TPM attestation is designed to avoid stable hardware tracking. The EK normally certifies other keys rather than directly signing application data. Anti-cheat systems often want the opposite property, a stable, non-spoofable hardware identity that survives account churn, operating-system reinstall, and local client tampering. That goal conflicts with the privacy shape of the TPM model.

The important distinction is that TPM attestation can make a hardware identity harder to forge, but only if the identity certificate is valid and the verifier refuses uncertified identity material.

## Consumer Failure Class 1, TPM Identity Breakage

The first consumer failure class is identity failure. If the verifier receives no usable Endorsement Certificate and does not already have the EK public key in an administrator-managed allowlist, the EK is just a key. It is not a trusted TPM identity.

Enterprise deployments can avoid that failure by controlling inventory. Microsoft describes [TPM key attestation](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/tpm-key-attestation) trust models where a Certification Authority (CA) establishes TPM trust through either the EK public key or the Endorsement Certificate.

That model works when an administrator enrolls devices before trusting them. A public anti-cheat service does not start with a complete allowlist of every legitimate consumer TPM.

Consumer platforms also produce non-malicious attestation failures. [FACEIT tells users](https://support.faceit.com/hc/en-us/articles/20669555338268-TPM-attestation-failed) that a TPM attestation failure can mean the service cannot verify TPM integrity.

AMD documents a consumer firmware TPM (fTPM) failure mode for AMD Secure Processor (ASP) fTPM implementations. [AMD states](https://www.amd.com/en/resources/support-articles/faqs/pa-420.html) that the failure can produce error code `0x80070490`.

AMD also says firmware updates were provided to motherboard manufacturers, but some motherboard manufacturers chose not to redistribute them.

This creates the anti-cheat policy problem. A strict verifier blocks legitimate users whose TPM path fails for firmware or platform-support reasons. A permissive verifier accepts unverifiable identity material and loses the hardware-rooted property it wanted. There is no TPM-only middle ground that preserves the same assurance.

The failure surface is wider because many consumer TPM deployments are firmware TPMs. [Intel describes Intel Platform Trust Technology (Intel PTT)](https://www.intel.com/content/www/us/en/support/articles/000094205/processors/intel-core-processors.html) as TPM functionality that resides in firmware. [Microsoft also notes](https://support.microsoft.com/en-us/windows/enable-tpm-2-0-on-your-pc-1fd5a332-360d-4f46-a1e7-ae6b0c90645c) that some retail motherboards ship with TPM turned off by default.

Those are normal consumer support states. They are not the clean, uniform assumptions of a managed attestation fleet.

## Consumer Failure Class 2, Measurement Breakage

A valid Endorsement Certificate proves something about the reporting TPM. It does not prove that the measurements are trustworthy. Measurement trust begins at the Static Root of Trust for Measurement (SRTM), and the Core Root of Trust for Measurement (CRTM) is the first code element that anchors that chain on a PC platform.

The PC Client Platform Firmware Profile states that the SRTM must come from an immutable portion of the host platform initialization code.

If the first measurement code is attacker-controlled, the TPM still works correctly. It records whatever digest it receives. The failure is outside the TPM. The measurement mechanism has been fed false input from the component it must already trust.

On consumer hardware, an anti-cheat cannot assume every platform enforces the SRTM property in a useful way. Users and vendors legitimately change firmware, UEFI variables, boot order, option ROM exposure, Secure Boot state, and bootloader configuration. [FACEIT explicitly treats](https://support.faceit.com/hc/en-us/articles/20669555338268-TPM-attestation-failed) self-signed boot loaders as unsupported.

The hard problem is interpreting difference. A changed PCR value proves that something changed. It does not, by itself, prove that the change is malicious.

## Reference Integrity Manifests and Interpretation

A PCR value becomes useful only when the verifier has reference data. TCG calls that reference data a Reference Integrity Manifest (RIM). A RIM lets a verifier validate expected assertions against measured evidence.

The event log itself is not trusted input. TCG event-log guidance treats it as untrusted and potentially malicious data.

The verifier can replay the log, compare the replayed PCR values against the quoted PCR values, and then compare each event against reference measurements. That process is manageable in a homogeneous fleet. It becomes much harder across arbitrary consumer hardware. TCG guidance notes that verifying arbitrarily ordered integrity measurements is complex.

Consumer anti-cheat systems do not have complete RIM coverage for every motherboard revision, firmware version, option ROM, bootloader path, Secure Boot state, and OEM update channel. Without that reference data, a verifier can say that a system is unusual. It cannot always say that the system is cheating.

Telemetry still helps. Rare measurement patterns, unexpected driver paths, and known cheat-specific firmware modifications are useful signals. They raise risk. They do not transform an unknown consumer platform into a known-good platform.

## Remaining Attack Vectors

Even a valid TPM identity and a replayable event log do not close every attack vector. A cuckoo attack proxies TPM commands to another genuine TPM that has cleaner state. [Parno describes](https://www.usenix.org/legacy/event/hotsec08/tech/full_papers/parno/parno_html/index.html) the core protocol failure as a naive design accepting evidence from the wrong platform.

The TPM on the other side of the proxy can have a valid Endorsement Certificate and a clean measurement log. From the verifier's perspective, the cryptographic transcript can look legitimate. The local gaming machine still may not be the machine that produced the TPM evidence.

The TCG Platform Certificate addresses this class of problem at the platform-binding layer. The TPM 2.0 Library, Part 0, describes it as assurance about the physical binding between the platform and the reporting root.

That does not fully solve consumer anti-cheat enforcement. Many consumer systems do not expose a platform-certificate chain that an anti-cheat can validate at scale. A discrete TPM (dTPM) can also be replaced. Requiring a firmware TPM, such as AMD fTPM or Intel PTT, raises the cost of simple module swapping, but it does not remove remote proxying or the compromised-local-client problem.

The local anti-cheat client can try to cross-check the event log against live kernel state. That check is still software running on the contested machine. An attacker who controls the local execution environment can patch, hide, or emulate the check.

## References

- Trusted Computing Group, [TCG Roots of Trust Specification](https://trustedcomputinggroup.org/wp-content/uploads/TCG_Roots_of_Trust_Specification_v0p20_PUBLIC_REVIEW.pdf).
- Trusted Computing Group, [TPM 2.0 Library, Part 0](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-0-Version-184_pub.pdf).
- Trusted Computing Group, [TPM 2.0 Library, Part 1](https://trustedcomputinggroup.org/wp-content/uploads/Trusted-Platform-Module-2.0-Library-Part-1-Version-184_pub.pdf).
- Trusted Computing Group, [TCG PC Client Platform Firmware Profile](https://trustedcomputinggroup.org/wp-content/uploads/PC-Client-Platform-Firmware-Profile-Version-1.06-Revision-52_pub.pdf).
- Trusted Computing Group, [TCG PC Client Reference Integrity Manifest](https://trustedcomputinggroup.org/wp-content/uploads/TCG-PC-Client-Reference-Integrity-Manifest-Version-1.1-Revision-10_18Oct2023.pdf).
- Trusted Computing Group, [TCG Guidance on Integrity Measurements and Event Log Processing](https://trustedcomputinggroup.org/wp-content/uploads/TCG-Guidance-Integrity-Measurements-Event-Log-Processing_V1.0_R131_PUB.pdf).
