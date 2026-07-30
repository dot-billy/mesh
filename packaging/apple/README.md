# Apple release evidence inventory

Apple artifacts in this checkout are unsupported source proofs. The canonical
Phase 9 inventory is
[`release-verification-matrix.json`](release-verification-matrix.json). It
lists every required gate for Mesh Admin on macOS, Mesh Node on macOS, Mesh
Admin on iPhone/iPad, and Mesh Tunnel on iPhone/iPad.

The matrix is a policy inventory, not evidence. It deliberately fixes
`release_eligible` to `false` and every product to `unsupported`. Run:

```text
python3 scripts/apple_release_matrix_verify.py
```

The v2 verifier rejects missing or duplicate gates, new proof classes, a
support claim, release eligibility, or any attempt to use a simulator group
for the iOS node. Every product must retain exact final source/provenance and
independent-verification gates. Both macOS products must retain exact release
metadata, authenticated-publication, public-re-download, and sanitized-receipt
gates. Mesh Node for macOS additionally requires the final signed bundle,
Installer signature, notarization/staple, and Gatekeeper gates. The iOS
products retain their channel-specific privacy or Network Extension approval
gates. Source and simulator receipts may establish only the source boundaries
they name. They cannot satisfy signing, notarization, protected release,
provenance, publication, native architecture, clean-host, physical-device,
accessibility, distribution, or packet-path classes.

Each future gate must retain its own bounded evidence through the
gate-specific verifier. A matrix entry is never a substitute for authenticating
the final artifact, receipt, host/device identity, exact test environment, and
authoritative readback. Release review may begin only after the product's
complete inventory has independently verified evidence and the canonical
public documentation describes the proved support level.

Managed application source examples are under
[`managed-configuration`](managed-configuration). They are unsigned and do
not satisfy an Apple release or deployment gate.
