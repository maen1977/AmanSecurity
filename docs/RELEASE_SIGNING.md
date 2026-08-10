# Android release signing

Aman 2.6 contains no keystore, password, signing secret, or environment-variable signing configuration in the project.

Android still requires release packages to be signed before distribution. Perform that normal publishing step outside the source tree with Android Studio, your app-store publishing flow, or another trusted local release process. This is independent from Aman threat-intelligence updates and is never required on user devices.
