plugins {
    kotlin("jvm") version "1.3.72"
}

group = "com.qverkk"
version = "1.0-SNAPSHOT"

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib-jdk8"))
    implementation("com.squareup.okhttp3:okhttp:4.6.0")
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-xml:2.11.0")
    implementation("commons-codec:commons-codec:1.14")
    implementation("com.squareup.okhttp3:logging-interceptor:4.6.0")
    implementation("com.squareup.okhttp3:okhttp-urlconnection:4.6.0")
}

tasks {
    compileKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
    compileTestKotlin {
        kotlinOptions.jvmTarget = "1.8"
    }
}