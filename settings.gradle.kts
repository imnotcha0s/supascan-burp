plugins {
    // Lets Gradle auto-provision the Java 17 toolchain on any machine that
    // doesn't already have one installed/detected.
    id("org.gradle.toolchains.foojay-resolver-convention") version "0.9.0"
}

rootProject.name = "supascan-burp"
