# Aman Security release rules.
# The app intentionally avoids reflection-heavy serialization frameworks.
# Android components referenced from the manifest are preserved by the Android Gradle Plugin.
# Keep source/line metadata so release crash reports remain actionable after R8 obfuscation.
-keepattributes SourceFile,LineNumberTable
-renamesourcefileattribute SourceFile
