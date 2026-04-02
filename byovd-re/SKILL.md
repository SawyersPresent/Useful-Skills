---
name: byovd-re
description: 
  Systematically analyze a Windows kernel driver binary for BYOVD-exploitable
  primitives. Covers surface mapping, access control, dispatch tracing, taint
  classification, false-positive elimination, and confirmed-only reporting.
tags: [driver, kernel, byovd, windows, ioctl]
---

## The Five Exploitation Questions

All five must be YES for a confirmed primitive:

1. Is the communication channel user-accessible? (SDDL / symlink verified)
2. Does an IOCTL/command reach the dangerous API?
3. Does the user control the destination/target?
4. Does the user control the source/value?
5. Does the user control the size/count?

For callback removal primitives: Q3/Q4/Q5 are N/A   sending the command IS the primitive.

## Compatibility

This workflow is Codex + MCP backend agnostic.

Required backend capabilities:
- enumerate imported/resolved kernel APIs
- decompile or disassemble functions and handlers
- traverse call graph/xrefs
- read raw memory bytes and pointer-sized values
- apply symbol renames and type annotations

If a backend lacks one capability, document that gap and downgrade confidence instead of guessing.

---
## MCP Backend Rules (Read First)

- **One heavy analysis call at a time**: do not parallelize decompile/disasm/xref-equivalent operations on fragile backends.
- **On timeout**: wait 10 seconds, retry once. If it still fails, mark `UNANALYZED` and continue.
- **UNICODE_STRING parsing**: read raw struct bytes first, then follow the `Buffer` pointer; do not rely on null-terminated string helpers.
- **Dispatch table pointers**: validate pointer math with raw memory reads, not only decompiler expressions.
- **Dynamic imports**: search string literals (`MmCopyMemory`, `IoCreateDeviceSecure`) and `MmGetSystemRoutineAddress` call sites because the static IAT may be incomplete.
- **Backend mapping**: if your MCP server uses different tool names, use equivalent capabilities (import list, decompile/disasm, xrefs, raw memory read, type annotation).

---

## Phase 1  Surface Mapping

**Goal**: Map the full attack surface. Do NOT assess exploitability yet   enumerate only.

### 1.1 Entry Point Analysis

1. Find `DriverEntry`   usually the binary entry point.
   - Signature: `NTSTATUS DriverEntry(DRIVER_OBJECT*, UNICODE_STRING*)`
   - Use your backend's decompile or disassembly view on the entry point.
2. From `DriverEntry`, extract:
   - `MajorFunction` dispatch table assignments
   - `DriverUnload` pointer
   - `DeviceName` and `SymbolicLinkName`
3. Apply types early: `DRIVER_OBJECT`, `DEVICE_OBJECT`, `IRP`, `IO_STACK_LOCATION`,
   `UNICODE_STRING`   apply type annotations/struct definitions in your backend to improve readability.

### 1.2 Dangerous Import Enumeration

Enumerate imported symbols and resolved APIs. Flag any of the following:

**Memory primitives**:
`MmMapIoSpace`, `MmMapIoSpaceEx`, `MmCopyMemory`, `MmGetPhysicalAddress`,
`MmMapLockedPagesSpecifyCache`, `MmMapLockedPages`, `IoAllocateMdl`, `MmProbeAndLockPages`

**Cross-process / attach**:
`KeStackAttachProcess`, `KeUnstackDetachProcess`, `ZwMapViewOfSection`,
`ZwOpenProcess`, `PsLookupProcessByProcessId`

**Kernel callback manipulation**:
`PsSetCreateProcessNotifyRoutine`, `PsSetCreateProcessNotifyRoutineEx`,
`PsSetCreateThreadNotifyRoutine`, `PsSetLoadImageNotifyRoutine`,
`ObRegisterCallbacks`, `CmRegisterCallbackEx`

**Token access**:
`PsReferencePrimaryToken`, `ObOpenObjectByPointer`, `SeQueryInformationToken`

**Dynamic resolution** (driver may resolve more APIs at runtime):
`MmGetSystemRoutineAddress`

Also search string literals for: `MmCopyMemory`, `IoCreateDeviceSecure`, `MmMapIoSpace`

### 1.3 Communication Channel Enumeration

Look for:
- `IoCreateDevice` / `IoCreateDeviceSecure` call sites â†’ device objects
- `IoCreateSymbolicLink` â†’ maps `\Device\X` to `\DosDevices\Global\X` (user-accessible)
- `FltCreateCommunicationPort` / `FltBuildDefaultSecurityDescriptor` â†’ minifilter ports
- `ZwCreateFile` with `\Device\` names â†’ internal channels (no symlink = not user-accessible)

### 1.4 IOCTL Code Enumeration

- Locate `MajorFunction[0xE]` in `DriverEntry` -> analyze `IRP_MJ_DEVICE_CONTROL` handler.
- List every IOCTL code in switch/if-else chains
- For minifilter ports: analyze `MessageNotifyCallback` and list every `cmd` value.

**Gate**: If zero user-accessible channels exist â†’ write false-positive report and stop.

---

## Phase 2  Access Control Verification

**Goal**: For every channel from Phase 1, determine the actual enforced security policy.
This is the most common source of false positives.

### 2.1 Device Object SDDL

For devices created with `IoCreateDeviceSecure` (or a dynamic thunk via
`MmGetSystemRoutineAddress`):

Read the `DefaultSDDLString` UNICODE_STRING:
```
Read raw UNICODE_STRING struct (x64, 16 bytes):
{ Length: WORD, MaxLength: WORD, _pad: DWORD, Buffer: QWORD }
Then follow Buffer pointer, read Length bytes, decode as UTF-16LE.
```

SDDL interpretation:
- `D:P` (empty protected DACL) â†’ **deny all**   remove from candidate list
- `D:P(A;;GA;;;AU)` â†’ any authenticated user   **in scope**
- `D:P(A;;GA;;;SY)` â†’ SYSTEM only   remove
- `D:P(A;;GA;;;BA)` â†’ Built-in Administrators only   in scope (elevated attacker)

For `IoCreateDevice` (no SDDL): access governed by object manager default   typically
requires admin.

### 2.2 Symlink Check

No symlink under `\DosDevices\Global\` = not accessible via `CreateFile("\\\\.\\Name")`.
Verify `IoCreateSymbolicLink` is called for the device. If absent â†’ remove from candidates.

### 2.3 IRP_MJ_CREATE Handler

Analyze `MajorFunction[0]` handler:
- Trivial `STATUS_SUCCESS` â†’ no additional gate
- `Irp->RequestorMode == KernelMode` check â†’ user-mode blocked regardless of SDDL
- Token integrity check â†’ low-integrity callers may be blocked

### 2.4 Minifilter Port Access

- `FltBuildDefaultSecurityDescriptor(FILE_ALL_ACCESS)` â†’ any authenticated user
- Check `ConnectNotifyCallback` for process name/PID gating or `MaxConnections = 1`

**Gate**: Remove deny-all and kernel-only channels. If none remain â†’ false-positive report
and stop.

---

## Phase 3   Dispatch Tracing

**Goal**: Trace every accessible IOCTL/command to every dangerous API call site.

### 3.1 IOCTL Handler Analysis

Analyze `IRP_MJ_DEVICE_CONTROL` for each accessible device. Look for:
- Switch on `IoControlCode`
- If/else chain on device object identity (multiple devices sharing one handler)
- Nested dispatch (outer routes to inner per-IOCTL functions)

Record per branch: IOCTL code, `InputBufferLength` checks, first sub-function called.

### 3.2 Call Chain Tracing

For each IOCTL branch, follow depth-first until hitting a dangerous API or dead end:
- Follow each function sequentially and keep heavy backend calls serialized when needed.
- Record full path: `dispatch â†’ sub_A â†’ sub_B â†’ DangerousAPI()`
- Note any conditional gates on the dangerous API call
- Rename functions as you understand them: `DispatchDeviceControl`, `HandleIoctlReadPhysMem`

### 3.3 Minifilter Message Path

- Analyze `MessageNotifyCallback`, map each `cmd` to its handler, and trace to dangerous APIs.
- Pre/post-op callbacks fire on filesystem I/O   tag as **kernel-event-triggered** (not
  user-on-demand)

---

## Phase 4   Parameter Taint Analysis

**Goal**: For each dangerous API call site, determine whether arguments are user-controlled.

### 4.1 Argument Tracing

For each argument register (`rcx`, `rdx`, `r8`, `r9`, stack) at the dangerous API call:

- `*(input_buffer + offset)` â†’ **DIRECT** (user-controlled   note offset and type)
- `PsGetCurrentProcessId()` â†’ **not user-controlled** (always caller's own PID)
- Hardcoded constant or global â†’ **not user-controlled**
- Conditional based on input â†’ **INDIRECT** (note constraint)

Check for dangerous patterns:
- Kernel write primitives: `KeSetEvent` with user-controlled address
- Missing `ProbeForRead`/`ProbeForWrite` before kernel-mode buffer copy
- Unchecked buffer sizes in `METHOD_NEITHER` IOCTLs   pool overflow
- `MmMapIoSpace` with user-supplied physical address   arbitrary physical memory access
- Direct stack buffer reads without size validation   kernel stack overflow
- `ObReferenceObjectByHandle` without proper access checks

### 4.2 Input Buffer Reconstruction

Find all `*(input + N)` reads in the dispatch chain. Infer types from usage. Build the
struct:

```c
struct DRIVER_WRITE_INPUT {
    /* +0x00 */ QWORD  DstVirtualAddress;
    /* +0x08 */ QWORD  SrcVirtualAddress;
    /* +0x10 */ DWORD  ByteCount;
    /* +0x14 */ DWORD  Flags;
};
// Min InputBufferLength: 0x18
```

### 4.3 Taint Tags

- **DIRECT**: user controls all meaningful parameters â†’ confirmed exploitable
- **INDIRECT**: user controls some but not all parameters
- **PASSIVE**: triggered by kernel events, not user IOCTL (MDL on filesystem I/O, token on
  process open)

---

## Phase 5   False Positive Elimination

Apply these patterns before declaring any primitive confirmed.

### FP1: Passive MDL â‰  Arbitrary Physical R/W

**Signature**: `MmMapLockedPagesSpecifyCache` + `IoAllocateMdl` + `MmProbeAndLockPages`

**Check**: What triggers the MDL operation?
- Minifilter pre/post-op callback â†’ **PASSIVE** â†’ downgrade to "passive I/O interception"
- User IOCTL with user-supplied src/dst/size â†’ **DIRECT** â†’ keep

### FP2: Token Query â‰  Token Theft

**Signature**: `PsReferencePrimaryToken` + `ObOpenObjectByPointer`

**Check**: What does the driver do with the token?
- Queries `TokenUser`/`TokenIntegrityLevel` for event records â†’ **NOT theft** â†’ downgrade
- Writes token to another process's `EPROCESS.Token` â†’ **DIRECT** â†’ keep

### FP3: Fixed PID Lookup â‰  Cross-Process Primitive

**Signature**: `ZwOpenProcess` or `PsLookupProcessByProcessId`

**Check**: Where does the PID originate?
- `PsGetCurrentProcessId()` â†’ **self-reference** â†’ downgrade to "self-process monitoring"
- `*(input_buffer + N)` (user-supplied) â†’ **DIRECT** â†’ keep

### FP4: Callback Registration â‰  Callback Removal

**Signature**: `PsSetCreateProcessNotifyRoutine`

**Check**: Is the registration function reachable from user input with NULL callback?
- Only registered at `DriverEntry`, never removed via user input â†’ **NOT exploitable**
- User-reachable command calls registration with NULL/removal flag â†’ **CONFIRMED: EDR
  blinding**

### FP5: Deny-All Device With Shared Handler

Two devices sharing one dispatch handler   only the accessible device's IOCTLs are in
scope. Verify the deny-all device has no user-mode path regardless of shared handler logic.

---

## Phase 6   Report

Write only confirmed, taint-verified primitives. False positives must be listed with
downgrade reasons.

```markdown
# BYOVD Vulnerability Report   [Driver Name]

## Driver Information
| Field | Value |
|-------|-------|
| Driver Name | |
| SHA256 | |
| Signed | Yes/No |
| LOLDrivers listed | Yes/No |
| Win10/Win11 blocked | Yes/No |

## Executive Summary
[What the driver does legitimately. What primitives are exposed. What an attacker can achieve.]

## Communication Channels (User-Accessible)
| Channel | Type | Access Policy |
|---------|------|--------------|

## Confirmed Vulnerabilities

### [1] [Technique Name]   [CRITICAL/HIGH/MEDIUM]
**IOCTL / Command**: `0xXXXXXXXX`
**Root Cause**: [API, why dangerous, what check is missing]
**Input Buffer**:
struct INPUT {
    /* +0x00 */ QWORD field;  // description
};
// Min InputBufferLength: N bytes
**Exploit Chain**:
1. CreateFile("\\\\.\\DeviceName", ...)
2. DeviceIoControl(hDev, 0xXXXXXXXX, &input, sizeof(input), ...)
3. Effect: [what happens in kernel]
**Prerequisites**: [local user / admin / specific context]
**HVCI impact**: [blocks / does not block]

## False Positives
| Technique | Scanner Verdict | Actual Behavior | Downgrade Reason |
|-----------|----------------|-----------------|-----------------|

## Mitigations
1. Vendor: [specific fix]
2. Defenders: WDAC policy / blocklist hash
3. Detection: [ETW event / IOCTL pattern]
```

### Pre-Publish Checklist
- [ ] Every confirmed primitive has a complete input buffer struct with field offsets
- [ ] Every false positive is listed with a specific downgrade reason
- [ ] Fidelity assessment present (always exploitable vs conditional)
- [ ] HVCI impact noted for each primitive
- [ ] No phantom primitives - only what was directly confirmed via trace-backed analysis

