# Apple managed configuration source examples

These files define the reviewed, non-secret Mesh Admin policy surface:

- `macos-admin.mobileconfig` is an **unsigned source example** using Apple's
  `com.apple.ManagedClient.preferences` payload. An approved MDM administrator
  must replace organization metadata as needed, sign the final profile, and
  validate it on managed macOS hardware before deployment.
- `ios-admin-managed-configuration.plist` is the dictionary to place in the
  MDM provider's Managed Application Configuration field for Mesh Admin. It is
  not a standalone installable configuration profile.

The exact accepted keys are `MeshManagedSchema`, `ControlPlaneOrigin`,
`AllowOriginChanges`, `ReleaseChannel`, `UpdateRing`, `ShowLocalStatus`, and
`NotificationsEnabled`. Unknown keys, wrong types, non-HTTPS origins, and
locked policy without an origin make Mesh Admin fail closed. `ReleaseChannel`
and `UpdateRing` are displayed policy labels only; they do not authorize a
download, update, rollback, or release selection. `ShowLocalStatus` is a
display policy only and does not grant Mesh Admin local node authority.

Never put enrollment or recovery material, sessions, cookies, access
credentials, private keys, or unrestricted enrollment authority in these
files.

No Packet Tunnel VPN or on-demand profile is published here. Apple requires
MDM for Per-App VPN, and a final profile must bind its `VPNSubType` to the
approved extension identifier. Mesh does not yet have approved production
Team/bundle identifiers, Network Extension capability evidence, a connected
physical iPhone/iPad, or a verified packet path. Reusing another application's
installed profile or inventing a provisional tunnel payload would create false
authority.

Engineering references:

- [Apple ManagedPreferences payload](https://developer.apple.com/documentation/devicemanagement/managedpreferences)
- [Apple Managed Application Configuration](https://developer.apple.com/documentation/devicemanagement/managed-application-configuration-command)
- [Apple declarative app configuration availability](https://support.apple.com/guide/deployment/declarative-app-configuration-dep80b8121d3/web)
- [Apple NETunnelProviderManager and Per-App VPN](https://developer.apple.com/documentation/networkextension/netunnelprovidermanager)

Run `python3 scripts/apple_managed_configuration_verify.py` from the repository
root before distributing either source example.
