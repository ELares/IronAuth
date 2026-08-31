// SPDX-License-Identifier: MIT OR Apache-2.0
import UIKit

/// The sample screen: a button, a label, and nothing else (issue #116).
///
/// Drop this into an app target and present it. The point of the file is how LITTLE there is:
/// no token storage, no refresh timer, no expiry arithmetic. `SignInCoordinator` owns the flow
/// and AppAuth owns the browser.
///
/// ## Two things to change before this runs
///
/// 1. `issuer` and `clientID` below.
/// 2. The redirect scheme in your app's `Info.plist`, under `CFBundleURLTypes`, matching the
///    scheme of `redirectURL`. Without it iOS has nowhere to deliver the callback and the
///    sign-in hangs on a browser that never closes -- which looks like a network problem and
///    is not.
public final class SignInViewController: UIViewController {

    /// The issuer, INCLUDING its tenant and environment path.
    private static let issuer = URL(string: "https://issuer.example/t/tnt_example/e/env_example")!

    /// The public client registered for this app.
    private static let clientID = "cli_example"

    /// Must be registered on the client, and its scheme declared in `CFBundleURLTypes`.
    private static let redirectURL = URL(string: "dev.ironauth.sample:/oauth2redirect")!

    private lazy var coordinator = SignInCoordinator(
        issuer: Self.issuer,
        clientID: Self.clientID,
        redirectURL: Self.redirectURL
    )

    private let status = UILabel()
    private let button = UIButton(type: .system)

    public override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .systemBackground

        status.numberOfLines = 0
        status.textAlignment = .center
        status.text = "Not signed in"

        button.setTitle("Sign in", for: .normal)
        button.addTarget(self, action: #selector(signInTapped), for: .touchUpInside)

        let stack = UIStackView(arrangedSubviews: [status, button])
        stack.axis = .vertical
        stack.spacing = 24
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 32),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -32)
        ])
    }

    @objc private func signInTapped() {
        status.text = "Signing in..."
        coordinator.signIn(presenting: self) { [weak self] result in
            // AppAuth calls back on the main queue, but stating it costs a line and removes a
            // question a reader would otherwise have to answer from the library's source.
            DispatchQueue.main.async {
                guard let self else { return }
                switch result {
                case .success(let session):
                    // The SUBJECT, not the token. Printing the token is the habit this sample
                    // exists partly to not teach.
                    self.status.text = "Signed in as \(session.subject)"
                case .failure(let error):
                    self.status.text = Self.describe(error)
                }
            }
        }
    }

    /// A message that points at the likely cause rather than restating the error.
    static func describe(_ error: SignInCoordinator.SignInError) -> String {
        switch error {
        case .discovery(let underlying):
            return "Discovery failed. Check the issuer includes its /t/<tenant>/e/<environment> path.\n\(String(describing: underlying))"
        case .authorization(let underlying):
            return "Authorization did not complete. If the browser never closed, check the redirect scheme is in CFBundleURLTypes.\n\(String(describing: underlying))"
        case .tokenExchange(let underlying):
            // The error a reader of this sample is most likely to hit, so it names the fix.
            return "Token exchange failed. On IronAuth this usually means the client needs the per-client bearer exemption, because AppAuth sends no DPoP proof. See docs/mobile-appauth.md.\n\(String(describing: underlying))"
        case .malformedResponse:
            return "Signed in, but the response carried no usable identity."
        }
    }
}
