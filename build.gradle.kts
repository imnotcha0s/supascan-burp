plugins {
    java
    id("com.gradleup.shadow") version "8.3.5"
}

group = "com.supascan"
version = "0.1.0"

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(17)
    }
}

repositories {
    mavenCentral()
}

dependencies {
    // Provided by Burp at runtime — compile only, never bundled.
    compileOnly("net.portswigger.burp.extensions:montoya-api:2024.+")
    // Bundled into the fat JAR (Burp does NOT provide it at runtime).
    implementation("com.google.code.gson:gson:2.11.0")
}

tasks.withType<JavaCompile>().configureEach {
    options.encoding = "UTF-8"
    // -serial: serialVersionUID on Swing panels is noise (Burp never serializes them).
    options.compilerArgs.addAll(listOf("-Xlint:all", "-Xlint:-processing", "-Xlint:-serial"))
}

tasks.shadowJar {
    archiveBaseName.set("supascan-burp")
    archiveClassifier.set("")
    archiveVersion.set(project.version.toString())
    // Relocate gson so it can never collide with another extension's copy.
    relocate("com.google.gson", "com.supascan.shaded.gson")
}

// `./gradlew jar` should produce the loadable (fat) JAR, per the spec.
tasks.named("jar") {
    dependsOn(tasks.shadowJar)
    enabled = false
}

tasks.build {
    dependsOn(tasks.shadowJar)
}
