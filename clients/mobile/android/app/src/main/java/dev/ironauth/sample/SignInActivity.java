// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.sample;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import net.openid.appauth.AuthorizationException;
import net.openid.appauth.AuthorizationRequest;
import net.openid.appauth.AuthorizationResponse;
import net.openid.appauth.AuthorizationService;
import net.openid.appauth.AuthorizationServiceConfiguration;
import net.openid.appauth.ResponseTypeValues;

/**
 * Sign a user into IronAuth from Android, over AppAuth (issue #116).
 *
 * <p>The whole flow is four steps and they are all here: discover, authorize in the SYSTEM
 * BROWSER, receive the redirect, exchange the code. AppAuth does the parts that are easy to
 * get subtly wrong -- Custom Tabs, PKCE, the redirect intent plumbing -- which is exactly why
 * IronAuth documents a path over it rather than shipping a mobile SDK.
 *
 * <h2>Two IronAuth-specific things a reader needs</h2>
 *
 * <p><b>The issuer carries a path.</b> An IronAuth issuer is per environment
 * ({@code https://host/t/<tenant>/e/<environment>}) while its endpoints sit at the host root,
 * so the discovery document is the only correct source for them. {@code fetchFromIssuer}
 * appends {@code /.well-known/openid-configuration} and reads what comes back; building
 * endpoint URLs by concatenating the issuer produces 404s.
 *
 * <p><b>AppAuth cannot do DPoP.</b> IronAuth requires DPoP from public clients by default,
 * and a mobile app is a public client. AppAuth has no DPoP support of any kind, so the client
 * this app uses must be granted the per-client exemption:
 *
 * <pre>{@code
 * PUT /v1/tenants/{tenant}/environments/{environment}/clients/{client_id}/bearer-tokens
 * {"allowed": true}
 * }</pre>
 *
 * <p>That is a real weakening and the environment's diagnostics will say so for as long as it
 * is set. `docs/mobile-appauth.md` covers what it costs and what the alternatives are.
 */
public final class SignInActivity extends Activity {

    private static final String TAG = "IronAuthSample";

    /**
     * The issuer, INCLUDING its tenant and environment path.
     *
     * <p>Replaced at build time in a real app; a literal here keeps the sample readable.
     */
    private static final String ISSUER = "https://issuer.example/t/tnt_example/e/env_example";

    /** The public client registered for this app. */
    private static final String CLIENT_ID = "cli_example";

    /**
     * The redirect, whose SCHEME must match {@code appAuthRedirectScheme} in build.gradle.kts
     * and whose whole value must be registered on the client.
     */
    private static final Uri REDIRECT_URI = Uri.parse("dev.ironauth.sample:/oauth2redirect");

    private static final int RC_AUTH = 100;

    private AuthorizationService service;
    private TextView status;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        status = new TextView(this);
        status.setPadding(48, 96, 48, 48);
        status.setText("Discovering...");
        setContentView(status);

        service = new AuthorizationService(this);

        // STEP 1: discovery. Never build the endpoints from the issuer string.
        AuthorizationServiceConfiguration.fetchFromIssuer(
                Uri.parse(ISSUER),
                (configuration, exception) -> {
                    if (configuration == null) {
                        show("Discovery failed: " + exception);
                        return;
                    }
                    startAuthorization(configuration);
                });
    }

    private void startAuthorization(AuthorizationServiceConfiguration configuration) {
        // STEP 2: the authorization request. PKCE is applied by AppAuth automatically --
        // there is no flag to set and no verifier to manage, which is most of why this
        // library is the documented path.
        AuthorizationRequest request =
                new AuthorizationRequest.Builder(
                                configuration, CLIENT_ID, ResponseTypeValues.CODE, REDIRECT_URI)
                        .setScope("openid profile offline_access")
                        .build();

        // The SYSTEM BROWSER, via Custom Tabs. Not a WebView: a WebView hands the app the
        // user's credentials as they type them, which is the practice RFC 8252 exists to end.
        startActivityForResult(service.getAuthorizationRequestIntent(request), RC_AUTH);
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode != RC_AUTH || data == null) {
            return;
        }
        // STEP 3: the redirect came back through AppAuth's receiver.
        AuthorizationResponse response = AuthorizationResponse.fromIntent(data);
        AuthorizationException failure = AuthorizationException.fromIntent(data);
        if (response == null) {
            show("Authorization failed: " + failure);
            return;
        }

        // STEP 4: the code exchange. This is the request IronAuth refuses with
        // `invalid_dpop_proof` unless the client is granted the bearer-token exemption,
        // because AppAuth sends no DPoP proof and a mobile app is a public client.
        service.performTokenRequest(
                response.createTokenExchangeRequest(),
                (tokens, exception) -> {
                    if (tokens == null) {
                        Log.w(TAG, "token exchange failed", exception);
                        show("Token exchange failed: " + exception);
                        return;
                    }
                    // A real app hands the token to its API layer and never logs it. Printing
                    // the SUBJECT rather than the token is the habit worth copying from here.
                    show("Signed in. sub=" + subjectOf(tokens.idToken));
                });
    }

    /** The `sub` from an ID token, for display only. */
    private static String subjectOf(String idToken) {
        if (idToken == null) {
            return "(no id_token)";
        }
        String[] segments = idToken.split("\\.");
        if (segments.length != 3) {
            return "(malformed)";
        }
        try {
            String claims =
                    new String(
                            android.util.Base64.decode(
                                    segments[1],
                                    android.util.Base64.URL_SAFE | android.util.Base64.NO_PADDING),
                            "UTF-8");
            return new org.json.JSONObject(claims).optString("sub", "(none)");
        } catch (Exception malformed) {
            return "(unreadable)";
        }
    }

    private void show(String message) {
        runOnUiThread(() -> status.setText(message));
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        service.dispose();
    }
}
