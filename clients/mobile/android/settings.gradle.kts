// SPDX-License-Identifier: MIT OR Apache-2.0
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "ironauth-appauth-sample"
include(":app")
