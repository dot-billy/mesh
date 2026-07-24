# Windows desktop package

`build-msix.ps1` packages a native Flutter release bundle as an unsigned,
per-user MSIX. It does not install the privileged Mesh node service.
The script validates the Flutter runtime payload, unpacks and checks the
finished package, rejects an embedded signature in CI, and writes a SHA-256
sidecar.

Run the script on Windows with Visual Studio and the Windows SDK installed:

```powershell
flutter build windows --release
packaging\desktop\windows\build-msix.ps1 `
  -BundlePath desktop\build\windows\x64\runner\Release `
  -IdentityName YOUR_PARTNER_CENTER_IDENTITY `
  -Publisher YOUR_CERTIFICATE_SUBJECT `
  -PublisherDisplayName YOUR_DISPLAY_NAME
```

The identity and publisher must match the signing certificate and, for Store
distribution, the values assigned in Partner Center. The script deliberately
leaves the package unsigned. The CI MSIX is therefore not a release artifact
and will not have normal publisher trust. A checksum proves download integrity;
it is not publisher authentication. Sign the MSIX only in a protected release
environment, then validate it with the Windows App Certification Kit and
install it on clean Windows 10 and Windows 11 systems before release.
