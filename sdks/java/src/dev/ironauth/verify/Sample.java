// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.verify;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Verify an IronAuth token against a live issuer, using only the JDK (issue #118, criterion 4).
 *
 * <pre>{@code
 * java dev.ironauth.verify.Sample https://issuer.example/t/tnt_1/e/env_1 cli_1 <token>
 * }</pre>
 *
 * <p>This is the "out of the box" path: discovery, then the key set, then verification, with no
 * dependency beyond the JDK. {@link IronAuthVerifier} deliberately does none of the fetching, so
 * this class is where the network policy lives and where a reader can see it all at once.
 *
 * <h2>The allow-list comes from the issuer, and you can watch it happen here</h2>
 *
 * <p>{@code id_token_signing_alg_values_supported} in the discovery document is what this passes
 * to the verifier. That is the whole defence against {@code alg: none} and HS256 forgery, and
 * writing it this way makes the rule visible rather than a sentence in a doc comment: the
 * algorithms come over the wire from the ISSUER, and the token never gets a say.
 *
 * <h2>What a real deployment must add</h2>
 *
 * <p>This fetches on every call. A production verifier caches the key set, refetches on an
 * unknown {@code kid} at a bounded rate, and keeps serving the cached set when the issuer is
 * briefly unreachable. That is left out on purpose: a cache with an eviction policy would be the
 * bulk of the file and would bury the four steps this exists to show.
 */
public final class Sample {

    private Sample() {}

    /** Discovery and JWKS are small; anything larger is a misconfiguration or an attack. */
    private static final int MAX_DOCUMENT_BYTES = 1 << 20;

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            System.err.println("usage: Sample <issuer> <audience> <token>");
            System.exit(2);
        }
        try {
            Map<String, Object> claims = verify(args[0], args[1], args[2]);
            System.out.println("verified: sub=" + claims.get("sub") + " iss=" + claims.get("iss"));
        } catch (IronAuthVerifier.VerifyException refused) {
            // The REASON is printed, not just "invalid token". A verifier that collapses every
            // refusal into one message makes a clock-skew outage indistinguishable from an
            // attack, which is how real incidents get misdiagnosed for hours.
            System.err.println("refused: " + refused.reason());
            System.exit(1);
        }
    }

    /** Discover, fetch keys, and verify. */
    public static Map<String, Object> verify(String issuer, String audience, String token)
            throws IOException, InterruptedException, IronAuthVerifier.VerifyException {
        HttpClient http = HttpClient.newBuilder()
                // NEVER: a redirect on discovery is an invitation to fetch someone else's keys.
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        Map<String, Object> discovery = fetchJson(http, issuer + "/.well-known/openid-configuration");

        // The issuer in the document must be the issuer we asked for. Without this check,
        // pointing at any URL gets you a document that names a different issuer and a key set to
        // match, and every later comparison passes against that attacker-chosen name.
        if (!issuer.equals(discovery.get("issuer"))) {
            throw new IllegalStateException("discovery names issuer " + discovery.get("issuer") + ", not " + issuer);
        }
        if (!(discovery.get("jwks_uri") instanceof String jwksUri)) {
            throw new IllegalStateException("discovery has no jwks_uri");
        }
        Set<String> algorithms = new LinkedHashSet<>();
        if (discovery.get("id_token_signing_alg_values_supported") instanceof List<?> published) {
            for (Object alg : published) {
                if (alg instanceof String name) {
                    algorithms.add(name);
                }
            }
        }
        // Belt and braces, and named as such: IronAuthVerifier already refuses `alg: none` by
        // name, so deleting this line changes no test and no outcome. It stays because this
        // class is also read as a template -- someone will lift this discovery code and pair it
        // with their own verifier -- and a metadata document that says `none` should never
        // become an allow-list entry in the first place.
        algorithms.remove("none");

        List<TrustedKey> keys = TrustedKey.fromJwks(fetchText(http, jwksUri));
        IronAuthVerifier verifier = new IronAuthVerifier(algorithms, keys, issuer, audience, 60);
        return verifier.verify(token, Instant.now().getEpochSecond());
    }

    private static Map<String, Object> fetchJson(HttpClient http, String url) throws IOException, InterruptedException {
        Object parsed = Json.parse(fetchText(http, url));
        if (parsed instanceof Map<?, ?> members) {
            @SuppressWarnings("unchecked")
            Map<String, Object> typed = (Map<String, Object>) members;
            return typed;
        }
        throw new IllegalStateException(url + " did not return a JSON object");
    }

    private static String fetchText(HttpClient http, String url) throws IOException, InterruptedException {
        URI uri = URI.create(url);
        // Plaintext is refused EXCEPT on loopback, which is what makes this sample testable
        // against a local server without leaving a switch someone can flip in production.
        boolean loopback = "localhost".equals(uri.getHost()) || "127.0.0.1".equals(uri.getHost()) || "[::1]".equals(uri.getHost());
        if (!"https".equals(uri.getScheme()) && !loopback) {
            throw new IllegalStateException("refusing to fetch issuer metadata over " + uri.getScheme());
        }
        HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(Duration.ofSeconds(5))
                .header("accept", "application/json")
                .GET()
                .build();
        HttpResponse<String> response = http.send(request, HttpResponse.BodyHandlers.ofString());
        if (response.statusCode() != 200) {
            throw new IOException(url + " returned " + response.statusCode());
        }
        String body = response.body();
        if (body.length() > MAX_DOCUMENT_BYTES) {
            throw new IOException(url + " returned " + body.length() + " bytes");
        }
        return body;
    }
}
