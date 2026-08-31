// SPDX-License-Identifier: MIT OR Apache-2.0
plugins { id("com.android.application") }

android {
    namespace = "dev.ironauth.sample"
    compileSdk = 34

    defaultConfig {
        applicationId = "dev.ironauth.sample"
        // 23 is AppAuth's own floor and covers essentially every device in service.
        minSdk = 23
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        // THE REDIRECT SCHEME, and AppAuth will not build without it: its manifest declares
        // a `RedirectUriReceiverActivity` whose intent filter interpolates this placeholder.
        // Omitting it fails the manifest merge with "requires a placeholder substitution",
        // which is the build telling you that a redirect nothing can deliver is not a
        // redirect. It must match the scheme of the redirect URI registered on the client.
        manifestPlaceholders["appAuthRedirectScheme"] = "dev.ironauth.sample"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    // THE ONLY DEPENDENCY. AppAuth implements RFC 8252 correctly -- system browser via
    // Custom Tabs, PKCE, and the redirect plumbing -- and re-implementing that by hand is
    // how native apps end up embedding a WebView, which is the thing RFC 8252 exists to
    // stop.
    implementation("net.openid:appauth:0.11.1")
}
