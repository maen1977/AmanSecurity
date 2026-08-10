# Android release signing

Aman 2.7 contains no keystore, password, private signing key, or threat-update signing secret in the project.

Android release artifacts must still be signed before public distribution. Perform normal release signing in Android Studio, your app-store publishing flow, or another trusted release environment. The automatic repository workflow intentionally publishes an installable debug APK for testing and an unsigned release AAB for downstream signing/distribution.

## Optional runtime signer pin

Aman 2.7 can compare its installed signing certificate to an expected **public** SHA-256 fingerprint. For the production build, provide:

```text
AMAN_RELEASE_CERT_SHA256=<64-hex-public-certificate-fingerprint>
```

as a Gradle property in the trusted release environment. This fingerprint is not secret. Never place the private signing key or keystore in the source tree.

If the property is absent, Aman reports that a signed release is unpinned instead of pretending that release identity was verified. Debug builds are explicitly identified as development builds.
