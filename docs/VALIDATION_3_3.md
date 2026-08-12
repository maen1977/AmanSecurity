# Aman Security 3.3.0 validation note

Local repository gates verify version 3.3.0/code 23, localization parity, Android API compatibility guards, the lightweight antivirus schedule, local attack prevention, Attack Detection Center integration, and the new Data Exfiltration Guard policy.

The new guard is intentionally conservative: raw upload volume alone stays CLEAR. HIGH requires background upload plus corroborating sideload/control/surveillance evidence, while system apps are excluded from traffic-policy escalation. The immediate DNS-event path only warns for apps already classified HIGH by the existing multi-signal spyware policy and explicitly states that a network contact is not proof that data was transferred.

A full Android Gradle/Lint build still needs the Android SDK/Gradle environment used by CI. Repository-local gates and the Android-free policy smoke test do not replace that final CI build.
