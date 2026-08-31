// SPDX-License-Identifier: MIT OR Apache-2.0
using System.Globalization;
using System.Text.Json;

namespace IronAuth.Verify;

/// <summary>
/// Verify an IronAuth token against a live issuer (issue #118, criterion 5).
/// </summary>
/// <remarks>
/// <para>
/// This is the "out of the box" path: discovery, then the key set, then verification.
/// <see cref="IronAuthVerifier"/> deliberately does none of the fetching, so this class is where
/// the network policy lives and where a reader can see all of it at once.
/// </para>
/// <para>
/// <b>The allow-list comes from the issuer, and you can watch it happen here.</b>
/// <c>id_token_signing_alg_values_supported</c> in the discovery document is what gets passed to
/// the verifier. That is the whole defence against <c>alg: none</c> and HS256 forgery, and writing
/// it this way makes the rule visible rather than a sentence in a doc comment.
/// </para>
/// <para>
/// A real deployment must add caching: this fetches on every call. A production verifier caches
/// the key set, refetches on an unknown <c>kid</c> at a bounded rate, and keeps serving the cached
/// set through a brief issuer outage. That is left out because a cache with an eviction policy
/// would be most of the file and would bury the four steps this exists to show.
/// </para>
/// </remarks>
public static class Sample
{
    /// <summary>Discovery and JWKS are small; anything larger is a misconfiguration or an attack.</summary>
    public const int MaxDocumentBytes = 1 << 20;

    /// <summary>Discover, fetch keys, and verify.</summary>
    /// <param name="http">the client to use; the caller owns its lifetime</param>
    /// <param name="issuer">the issuer to discover, compared exactly against the document</param>
    /// <param name="audience">the expected audience</param>
    /// <param name="token">the token to verify</param>
    /// <param name="nowEpochSeconds">the instant to judge the token at</param>
    /// <returns>the verified claims</returns>
    public static async Task<JsonElement> VerifyAsync(
        HttpClient http,
        string issuer,
        string audience,
        string token,
        long nowEpochSeconds)
    {
        ArgumentNullException.ThrowIfNull(http);
        ArgumentNullException.ThrowIfNull(issuer);

        using JsonDocument discovery = JsonDocument.Parse(
            await FetchAsync(http, issuer + "/.well-known/openid-configuration").ConfigureAwait(false));

        // The issuer in the document must be the issuer we asked for. Without this check, pointing
        // at any URL yields a document naming a different issuer and a key set to match, and every
        // later comparison passes against that attacker-chosen name.
        string? named = discovery.RootElement.TryGetProperty("issuer", out JsonElement issuerElement)
            ? issuerElement.GetString()
            : null;
        if (named != issuer)
        {
            throw new InvalidOperationException($"discovery names issuer {named}, not {issuer}");
        }
        if (!discovery.RootElement.TryGetProperty("jwks_uri", out JsonElement jwksElement)
            || jwksElement.GetString() is not string jwksUri)
        {
            throw new InvalidOperationException("discovery has no jwks_uri");
        }

        HashSet<string> algorithms = [];
        if (discovery.RootElement.TryGetProperty("id_token_signing_alg_values_supported", out JsonElement published)
            && published.ValueKind == JsonValueKind.Array)
        {
            foreach (JsonElement alg in published.EnumerateArray())
            {
                if (alg.ValueKind == JsonValueKind.String && alg.GetString() is string name)
                {
                    algorithms.Add(name);
                }
            }
        }
        // Belt and braces, and named as such: IronAuthVerifier already refuses `alg: none` by
        // name, so deleting this line changes no test and no outcome. It stays because this class
        // is also read as a template, and a metadata document that says `none` should never become
        // an allow-list entry in the first place.
        algorithms.Remove("none");

        IReadOnlyList<TrustedKey> keys = TrustedKey.FromJwks(await FetchAsync(http, jwksUri).ConfigureAwait(false));
        IronAuthVerifier verifier = new(algorithms, keys, issuer, audience, 60);
        return verifier.Verify(token, nowEpochSeconds);
    }

    private static async Task<string> FetchAsync(HttpClient http, string url)
    {
        Uri uri = new(url);
        // Plaintext is refused EXCEPT on loopback, which is what makes this sample testable
        // against a local server without leaving a switch someone can flip in production.
        bool loopback = uri.IsLoopback;
        if (uri.Scheme != Uri.UriSchemeHttps && !loopback)
        {
            throw new InvalidOperationException($"refusing to fetch issuer metadata over {uri.Scheme}");
        }

        using HttpResponseMessage response = await http
            .GetAsync(uri, HttpCompletionOption.ResponseHeadersRead)
            .ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new HttpRequestException(
                string.Create(CultureInfo.InvariantCulture, $"{url} returned {(int)response.StatusCode}"));
        }

        // ResponseHeadersRead plus a bounded read, NOT ReadAsStringAsync: the latter buffers the
        // WHOLE body before returning, so a length check afterwards runs only once the memory is
        // already spent. The bound would read like a defence and stop nothing.
        using Stream stream = await response.Content.ReadAsStreamAsync().ConfigureAwait(false);
        using MemoryStream collected = new();
        byte[] buffer = new byte[8192];
        int read;
        while ((read = await stream.ReadAsync(buffer).ConfigureAwait(false)) != 0)
        {
            await collected.WriteAsync(buffer.AsMemory(0, read)).ConfigureAwait(false);
            if (collected.Length > MaxDocumentBytes)
            {
                throw new HttpRequestException(
                    string.Create(CultureInfo.InvariantCulture, $"{url} returned more than {MaxDocumentBytes} bytes"));
            }
        }
        return System.Text.Encoding.UTF8.GetString(collected.ToArray());
    }
}
