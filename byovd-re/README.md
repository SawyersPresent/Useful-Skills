# byovd-re Skill

High-confidence BYOVD (Bring Your Own Vulnerable Driver) reverse-engineering workflow for Windows `.sys` drivers.

This package is designed for AI-assisted triage and reporting, with strict confirmed-only standards:

- Channel reachability must be proven
- Dispatch path must be traced end-to-end
- Parameter taint must be verified
- False positives must be explicitly ruled out

## Folder Layout

- `SKILL.md` - primary skill workflow
- `references/BYOVD-RE.md` - full methodology reference (generalized for Codex + any compatible MCP backend)
- `references/README.md` - upstream BYOVD reference notes

## Compatibility

- Works with Codex using any reverse-engineering MCP server that provides:
  - decompile or disassembly views
  - xrefs/call graph traversal
  - import/symbol visibility
  - raw memory byte and pointer reads
  - symbol rename/type annotation support
- Not limited to Vendor Specific RE Products.

## Recommended Use Cases

- Validate whether a flagged driver primitive is truly exploitable
- Produce evidence-backed BYOVD reports with reproducible trace paths
- Separate confirmed vulnerabilities from scanner-only hypotheses

## Not In Scope

- Malware development
- Exploit weaponization
- Evasion/persistence implementation

## Typical Prompt

```
Use byovd-re to analyze this Windows kernel driver. I need confirmed-only findings with:
1) channel reachability,
2) IOCTL/dispatch-to-sink trace,
3) taint classification,
4) false-positive elimination,
5) final report table.
```

## Expected Output

- Driver/channel summary
- Confirmed primitives (only)
- Rejected/false-positive candidates with reason
- Severity and ATT&CK mapping where applicable
- Mitigation and retest checklist

## Installation (Local)

1. Copy this folder to your assistant skills directory as `byovd-re`.
2. Ensure the skill file is available at `.../byovd-re/SKILL.md`.
3. Invoke the skill by name in your AI workflow.
