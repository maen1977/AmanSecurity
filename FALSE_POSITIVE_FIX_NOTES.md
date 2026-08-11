# False-positive correction

- Malware score is separated from permission/privacy capability review.
- Android UNKNOWN installer source is not treated as sideload evidence.
- Only explicit LOCAL_FILE / DOWNLOADED_FILE sources add non-store-install evidence.
- Brand-token overlap alone no longer triggers impersonation detection for sibling vendor packages.
- Static capabilities/local model alone are capped below antivirus REVIEW unless malware-specific evidence exists.
- Installed-app antivirus score comes from the multi-engine malware verdict, not permission breadth.
- Standalone APK malware score follows the same separation.
- Privacy-sensitive permissions remain available through Permissions Control.
