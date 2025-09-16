plugins {
    id("java")
    id("com.github.johnrengelman.shadow") version "8.1.1"
}

group = "example.application"
version = "1.0-SNAPSHOT"

dependencies {
    // msal4j
    implementation(group="com.microsoft.azure", name="msal4j", version="1.23.0")

    // okhttp/retrofit
    implementation(group="com.squareup.okhttp3", name="logging-interceptor", version="5.1.0")
    implementation(group="com.squareup.okhttp3", name="okhttp", version="5.1.0")

    // slf4j
    implementation(group="org.slf4j", name="slf4j-api", version="2.0.17")
    implementation(group="org.slf4j", name="slf4j-simple", version="2.0.17")

    // microprofile
    implementation(group="org.eclipse.microprofile", name="microprofile", version="7.1")
    implementation(group="io.smallrye.config", name="smallrye-config", version="3.10.2")

    // testing
    testImplementation(group="com.squareup.okhttp3", name="mockwebserver", version="5.1.0")
    testImplementation(group="io.fabric8", name="mockwebserver", version="7.3.1")
    testImplementation(platform("org.junit:junit-bom:5.13.4"))
    testImplementation(group="org.junit.jupiter", name="junit-jupiter")
    testRuntimeOnly(group="org.junit.platform", name="junit-platform-launcher")
    testImplementation(group="org.mockito", name="mockito-core", version="5.18.0")
}

repositories {
    mavenCentral()
}

tasks {
    build {
        dependsOn(shadowJar) // required to build a fat jar
    }
    test {
        useJUnitPlatform()
    }
    wrapper {
        gradleVersion = "8.10"
        distributionType = Wrapper.DistributionType.ALL
    }
}
