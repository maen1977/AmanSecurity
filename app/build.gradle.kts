import org.jetbrains.kotlin.gradle.dsl.JvmTarget

val expectedReleaseCertRaw = providers.gradleProperty("AMAN_RELEASE_CERT_SHA256").orNull.orEmpty().trim().lowercase()
val expectedReleaseCert = expectedReleaseCertRaw.takeIf { Regex("^[a-f0-9]{64}$").matches(it) }.orEmpty()

val cloudThreatDbBaseUrlRaw = providers.environmentVariable("AMAN_THREAT_DB_BASE_URL").orNull
    ?: providers.gradleProperty("AMAN_THREAT_DB_BASE_URL").orNull
    ?: "https://raw.githubusercontent.com/maen1977/AmanSecurity-Threat-DB/main/latest"
val cloudThreatDbBaseUrl = cloudThreatDbBaseUrlRaw.trim().replace("\\", "\\\\").replace("\"", "\\\"")

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.aman.security"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.aman.security"
        minSdk = 26
        targetSdk = 36
        versionCode = 79
        versionName = "1.1.1.6"

        buildConfigField("String", "EXPECTED_RELEASE_CERT_SHA256", "\"$expectedReleaseCert\"")
        buildConfigField("String", "AMAN_THREAT_DB_BASE_URL", "\"$cloudThreatDbBaseUrl\"")

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
    }


    buildFeatures {
        viewBinding = true
        buildConfig = true
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            isDebuggable = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    lint {
        abortOnError = true
        checkReleaseBuilds = true
        warningsAsErrors = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_17)
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.17.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.11.0")
    implementation("com.google.android.material:material:1.13.0")
    implementation("androidx.work:work-runtime-ktx:2.10.1")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.json:json:20240303")
}
