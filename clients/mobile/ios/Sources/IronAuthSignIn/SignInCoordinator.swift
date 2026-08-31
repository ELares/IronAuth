// SPDX-License-Identifier: MIT OR Apache-2.0
import AppAuth
import Foundation
import UIKit

/// Sign a user into IronAuth from iOS, over AppAuth (issue #116).
///
/// The flow is four steps and they are all here: discover, authorize in the system browser,
/// receive the redirect, exchange the code. AppAuth does the parts that are easy to get subtly
/// wrong, which is exactly why IronAuth documents a path over it rather than shipping an SDK.
///
/// ## Two IronAuth-specific things
///
/// **The issuer carries a path.** An IronAuth issuer is per environment
/// (`https://host/t/<tenant>/e/<environment>`) while its endpoints sit at the host root, so the
/// discovery document is the only correct source for them. `discoverConfiguration(forIssuer:)`
/// appends `/.well-known/openid-configuration` and reads what comes back; building endpoint URLs
/// by concatenating the issuer produces 404s.
///
/// **AppAuth cannot do DPoP.** IronAuth requires DPoP from public clients by default and a
/// mobile app is a public client, so the client this app uses must be granted the per-client
/// exemption. See `docs/mobile-appauth.md`, which states what that costs.
public final class SignInCoordinator {

    /// What a completed sign-in yields the caller.
    public struct Session {
        /// The subject of the ID token.
        public let subject: String
        /// The access token. Hand it to your API layer; never log it.
        public let accessToken: String
    }

    /// Why a sign-in did not complete.
    public enum SignInError: Error {
        /// Discovery failed, or named endpoints this client cannot use.
        case discovery(Error?)
        /// The user cancelled, or the authorization leg failed.
        case authorization(Error?)
        /// The token exchange failed. On IronAuth the usual cause is a missing DPoP proof:
        /// AppAuth sends none, so the client needs the per-client bearer exemption.
        case tokenExchange(Error?)
        /// The exchange succeeded but returned no usable identity.
        case malformedResponse
    }

    private let issuer: URL
    private let clientID: String
    private let redirectURL: URL
    private let scopes: [String]

    /// The in-flight authorization session, held so it is not deallocated mid-flow.
    ///
    /// AppAuth returns this and expects the caller to keep it: dropping it tears down the
    /// browser session, and the symptom is a sign-in that silently never returns.
    private var session: OIDExternalUserAgentSession?

    /// - Parameters:
    ///   - issuer: the issuer INCLUDING its tenant and environment path
    ///   - clientID: the public client registered for this app
    ///   - redirectURL: must be registered on the client, and its scheme must be declared in
    ///     the app's `CFBundleURLTypes`
    ///   - scopes: requested scopes
    public init(
        issuer: URL,
        clientID: String,
        redirectURL: URL,
        scopes: [String] = [OIDScopeOpenID, OIDScopeProfile]
    ) {
        self.issuer = issuer
        self.clientID = clientID
        self.redirectURL = redirectURL
        self.scopes = scopes
    }

    /// Run the whole flow, presenting the system browser from `presenter`.
    public func signIn(
        presenting presenter: UIViewController,
        completion: @escaping (Result<Session, SignInError>) -> Void
    ) {
        // STEP 1: discovery. Never build the endpoints from the issuer string.
        OIDAuthorizationService.discoverConfiguration(forIssuer: issuer) { [weak self] configuration, error in
            guard let self else { return }
            guard let configuration else {
                completion(.failure(.discovery(error)))
                return
            }
            self.authorize(with: configuration, presenting: presenter, completion: completion)
        }
    }

    private func authorize(
        with configuration: OIDServiceConfiguration,
        presenting presenter: UIViewController,
        completion: @escaping (Result<Session, SignInError>) -> Void
    ) {
        // STEP 2: the authorization request. PKCE is applied by AppAuth automatically -- there
        // is no flag to set and no verifier to manage.
        let request = OIDAuthorizationRequest(
            configuration: configuration,
            clientId: clientID,
            clientSecret: nil,
            scopes: scopes,
            redirectURL: redirectURL,
            responseType: OIDResponseTypeCode,
            additionalParameters: nil
        )

        // STEPS 3 AND 4: AppAuth presents the SYSTEM BROWSER, receives the redirect, and
        // performs the code exchange. `authState(byPresenting:)` is the one call that covers
        // all three, which is why this file is short.
        session = OIDAuthState.authState(byPresenting: request, presenting: presenter) { state, error in
            guard let state else {
                completion(.failure(.authorization(error)))
                return
            }
            guard let accessToken = state.lastTokenResponse?.accessToken else {
                // The authorization leg succeeded and the EXCHANGE did not. On IronAuth the
                // usual cause is the DPoP posture: AppAuth sends no proof.
                completion(.failure(.tokenExchange(error)))
                return
            }
            guard let subject = Self.subject(of: state.lastTokenResponse?.idToken) else {
                completion(.failure(.malformedResponse))
                return
            }
            completion(.success(Session(subject: subject, accessToken: accessToken)))
        }
    }

    /// The `sub` claim of an ID token, for display.
    ///
    /// UNVERIFIED, and deliberately so: the token was just obtained over TLS from the endpoint
    /// discovery named, and this value is only ever shown to the user who signed in. A resource
    /// server must verify signatures; a screen showing "signed in as" need not, and pretending
    /// otherwise here would suggest this is a verification routine that other code could reuse.
    static func subject(of idToken: String?) -> String? {
        guard let idToken else { return nil }
        let segments = idToken.split(separator: ".")
        guard segments.count == 3 else { return nil }

        var encoded = String(segments[1])
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        // Base64url drops the padding that `Data(base64Encoded:)` requires.
        while encoded.count % 4 != 0 {
            encoded.append("=")
        }
        guard let data = Data(base64Encoded: encoded),
              let claims = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let subject = claims["sub"] as? String
        else {
            return nil
        }
        return subject
    }
}
