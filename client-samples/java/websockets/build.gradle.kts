plugins {
    id("java")
    id("com.gradleup.shadow") version "8.3.5"
}

group = "example.application"
version = "1.0-SNAPSHOT"

var microsoftAzureMsal4jVersion = "1.17.3";
var squareupOkhttp3Version = "4.11.0";
var slf4jVersion = "2.0.16";
var eclipseMicroprofileVersion = "6.0";
var smallRyeConfigVersion = "3.9.1";
var squareupOkhttp3MockwebserverVersion = "4.12.0";
var ioFabric8MockwebserverVersion = "0.1.8";
var junitJupiterVersion = "5.11.3";
var mockitoCoreVersion = "5.14.2";

dependencies {
    // msal4j
    implementation(group="com.microsoft.azure", name="msal4j", version=microsoftAzureMsal4jVersion)

    // okhttp/retrofit
    implementation(group="com.squareup.okhttp3", name="logging-interceptor", version=squareupOkhttp3Version)
    implementation(group="com.squareup.okhttp3", name="okhttp", version=squareupOkhttp3Version)

    // slf4j
    implementation(group="org.slf4j", name="slf4j-api", version=slf4jVersion)
    implementation(group="org.slf4j", name="slf4j-simple", version=slf4jVersion)

    // microprofile
    implementation(group="org.eclipse.microprofile", name="microprofile", version=eclipseMicroprofileVersion)
    implementation(group="io.smallrye.config", name="smallrye-config", version=smallRyeConfigVersion)

    // testing
    testImplementation(group="com.squareup.okhttp3", name="mockwebserver", version=squareupOkhttp3MockwebserverVersion)
    testImplementation(group="io.fabric8", name="mockwebserver", version=ioFabric8MockwebserverVersion)
    testImplementation(group="org.junit.jupiter", name="junit-jupiter", version=junitJupiterVersion)
    testImplementation(group="org.mockito", name="mockito-core", version=mockitoCoreVersion)
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
