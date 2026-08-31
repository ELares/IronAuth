// swift-tools-version: 5.9
// SPDX-License-Identifier: MIT OR Apache-2.0
import PackageDescription

// The iOS sign-in sample (issue #116, criterion 7).
//
// A LIBRARY TARGET rather than an Xcode app project, and the reason is worth stating: what is
// worth verifying here is that the integration code compiles against the REAL AppAuth API, and
// a library target gets that under `xcodebuild -destination 'generic/platform=iOS'` without a
// hand-written `.xcodeproj` that nothing would check. Drop these files into an app target and
// present `SignInViewController`; that is the whole integration.
let package = Package(
    name: "IronAuthSignIn",
    // iOS 15, because AppAuth-iOS declares that floor and SwiftPM requires a consumer to be at
    // or above its dependency's. Declaring .v13 here resolves to a refusal, not a warning:
    // "requires minimum platform version 15.0 ... but ... supports 13.0". Checked against the
    // dependency's own manifest rather than guessed, since nothing local can compile this.
    platforms: [.iOS(.v15)],
    products: [
        .library(name: "IronAuthSignIn", targets: ["IronAuthSignIn"])
    ],
    dependencies: [
        // AppAuth implements RFC 8252 correctly: ASWebAuthenticationSession, PKCE, and the
        // redirect plumbing. Re-implementing that by hand is how native apps end up embedding
        // a WKWebView, which is the practice RFC 8252 exists to end.
        .package(url: "https://github.com/openid/AppAuth-iOS.git", from: "1.7.5")
    ],
    targets: [
        .target(
            name: "IronAuthSignIn",
            dependencies: [.product(name: "AppAuth", package: "AppAuth-iOS")]
        )
    ]
)
