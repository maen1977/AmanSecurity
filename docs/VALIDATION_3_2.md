# Aman Security 3.2.0 validation note

Local validation for this source package includes the Python quality gate, Android XML parsing, string/reference parity, the 3.2 Attack Detection Center source gate, and the existing detection regression benchmark.

The Attack Detection Center intentionally performs no additional background scanning. It reads the existing bounded local event timeline only when the UI/status notification is refreshed. Android Gradle unit tests, release lint, and APK/AAB compilation still require the repository GitHub Android toolchain when no local Android SDK/Gradle wrapper is available.
