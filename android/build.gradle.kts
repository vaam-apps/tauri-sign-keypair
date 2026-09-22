plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.vaam.signkeypair"
    compileSdk = 36

    defaultConfig {
        // BiometricPrompt's crypto-backed authentication needs 23+, and
        // `setUserAuthenticationParameters` — per-operation authorisation with
        // the device credential accepted alongside biometrics — needs 30. Below
        // 30 the user-present key is biometric-only; see
        // SecureKeyStore.createKeyPair, which says so rather than papering over
        // it.
        minSdk = 24

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("proguard-rules.pro")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("com.fasterxml.jackson.core:jackson-databind:2.15.3")
    implementation(project(":tauri-android"))

    testImplementation("junit:junit:4.13.2")
    testImplementation(kotlin("test"))
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test:runner:1.5.2")
}
