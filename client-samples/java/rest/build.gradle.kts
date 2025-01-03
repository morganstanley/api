plugins {
    id("java")
    id("com.gradleup.shadow") version "8.3.5"
}

group = "example.application"
version = "1.0-SNAPSHOT"

dependencies {
    implementation(group="com.google.guava", name="guava", version="${property("googleGuavaVersion")}")
    implementation(group="com.microsoft.azure", name="msal4j", version="${property("microsoftAzureMsal4jVersion")}")
    implementation(group="com.auth0", name="java-jwt", version="${property("auth0JavaJwtVersion")}")

    // okhttp/retrofit
    implementation(group="com.squareup.okhttp3", name="logging-interceptor", version="${property("squareupOkhttp3Version")}")
    implementation(group="com.squareup.okhttp3", name="okhttp", version="${property("squareupOkhttp3Version")}")
    implementation(group="com.squareup.retrofit2", name="converter-jackson", version="${property("squareupRetrofit2Version")}")
    implementation(group="com.squareup.retrofit2", name="retrofit", version="${property("squareupRetrofit2Version")}")

    // slf4j
    implementation(group="org.slf4j", name="slf4j-api", version="${property("slf4jVersion")}")
    implementation(group="org.slf4j", name="slf4j-simple", version="${property("slf4jVersion")}")

    // microprofile
    implementation(group="org.eclipse.microprofile", name="microprofile", version="${property("eclipseMicroprofileVersion")}")
    implementation(group="org.eclipse.microprofile.config", name="microprofile-config-api", version="${property("eclipseMicroprofileConfigVersion")}")
    implementation(group="io.smallrye.config", name="smallrye-config", version="${property("smallRyeConfigVersion")}")
    implementation(group="org.osgi", name="org.osgi.annotation.bundle", version= "${property("osgiAnnotationBundleVersion")}")
    implementation(group="jakarta.annotation", name="jakarta.annotation-api", version="${property("jakartaAnnotationVersion")}")

    // testing
    testImplementation(group="com.squareup.okhttp3", name="mockwebserver", version="${property("squareupOkhttp3MockwebserverVersion")}")
    testImplementation(group="org.junit.jupiter", name="junit-jupiter", version="${property("junitJupiterVersion")}")
    testImplementation(group="org.mockito", name="mockito-core", version="${property("mockitoCoreVersion")}")
}

repositories {
    mavenCentral()
}

tasks {
    build {
        dependsOn(shadowJar) // required to build a fat jar
    }
    jar {
        manifest {
            attributes(mapOf("Main-Class" to "com.ms.infra.example.application.ExampleApplication"))
        }
    }
    test {
        minHeapSize = "128m" // initial heap size
        maxHeapSize = "512m" // maximum heap size
        useJUnitPlatform()
    }
    wrapper {
        gradleVersion = "8.3"
        distributionType = Wrapper.DistributionType.ALL
    }
}
