// SPDX-License-Identifier: MIT OR Apache-2.0
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using IronAuth.Verify;
using Org.BouncyCastle.Crypto;

namespace IronAuth.Verify.Checks;

/// <summary>
/// Runs <see cref="Sample"/> end to end against a loopback issuer (issue #118).
/// </summary>
/// <remarks>
/// <see cref="Sample"/> is the artifact criterion 5 actually asks for. A sample nobody executes is
/// the failure mode worth avoiding: it compiles, it reads correctly, and it is wrong. So this
/// stands up a real HTTP listener publishing a real discovery document and a real JWK Set, mints a
/// real token, and drives the sample's whole path: discovery, <c>jwks_uri</c>, key decode,
/// algorithm allow-list, verification.
/// </remarks>
internal static class SampleHarness
{
    private static readonly List<string> Failures = [];
    private static int _checked;

    private static string _advertisedAlgorithms = """["EdDSA"]""";
    private static string _advertisedIssuer = string.Empty;
    private static bool _oversizeJwks;
    private static bool _redirectDiscovery;

    internal static async Task<int> RunAsync()
    {
        AsymmetricCipherKeyPair pair = Fixtures.GenerateEd25519();
        string x = Fixtures.PublicX(pair);
        // A second key, published only behind the redirect, so following it changes the answer.
        string elsewhereX = Fixtures.PublicX(Fixtures.GenerateEd25519());

        int port = FreePort();
        string simpleBase = string.Create(CultureInfo.InvariantCulture, $"http://127.0.0.1:{port}");
        _advertisedIssuer = simpleBase;

        using HttpListener listener = new();
        listener.Prefixes.Add(simpleBase + "/");
        listener.Start();
        using CancellationTokenSource stopping = new();
        Task serving = ServeAsync(listener, simpleBase, x, elsewhereX, stopping.Token);

        // Redirect.NEVER is not the default in .NET either, so the sample builds its own handler.
        using HttpClientHandler handler = new() { AllowAutoRedirect = false };
        using HttpClient http = new(handler) { Timeout = TimeSpan.FromSeconds(5) };

        try
        {
            long now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
            string claims = string.Create(CultureInfo.InvariantCulture,
                $$"""{"iss":"{{simpleBase}}","aud":"cli_sample","sub":"usr_sample","exp":{{now + 3600}},"nbf":{{now - 60}}}""");
            string token = Fixtures.Mint(pair, """{"alg":"EdDSA","typ":"JWT","kid":"sample-1"}""", claims);

            // THE SAMPLE ACTUALLY RUNS. Discovery, jwks_uri, key decode, verification.
            await CheckAsync("the sample verifies a live Ed25519 token end to end", async () =>
            {
                JsonElement verified = await Sample.VerifyAsync(http, simpleBase, "cli_sample", token, now).ConfigureAwait(false);
                return verified.GetProperty("sub").GetString() == "usr_sample" ? null : "sub was wrong";
            }).ConfigureAwait(false);

            // A tampered token over the same live path, so the harness cannot pass by never
            // reaching the verifier at all.
            string tampered = token[..^4] + "AAAA";
            await CheckAsync("a tampered token is refused over the same path", async () =>
            {
                try
                {
                    await Sample.VerifyAsync(http, simpleBase, "cli_sample", tampered, now).ConfigureAwait(false);
                    return "it verified";
                }
                catch (VerifyException refused)
                {
                    return refused.Reason == RejectReason.SignatureInvalid ? null : $"refused as {refused.Reason}";
                }
            }).ConfigureAwait(false);

            // An issuer advertising `none` must not talk the sample into accepting an unsigned
            // token. Note WHERE that is enforced: the refusal is AlgNone, which the verifier raises
            // by name, so this passes even with the sample's own `algorithms.Remove("none")`
            // deleted. Still worth running as the end-to-end statement, but it does not measure
            // that one line, and the Java sibling's mutation run said so.
            _advertisedAlgorithms = """["none","EdDSA"]""";
            string unsigned = Base64Url.Encode(Encoding.UTF8.GetBytes("""{"alg":"none","typ":"JWT"}"""))
                + "." + Base64Url.Encode(Encoding.UTF8.GetBytes(claims)) + ".";
            await CheckAsync("an issuer advertising `none` still cannot get an unsigned token accepted", async () =>
            {
                try
                {
                    await Sample.VerifyAsync(http, simpleBase, "cli_sample", unsigned, now).ConfigureAwait(false);
                    return "it verified";
                }
                catch (VerifyException refused)
                {
                    return refused.Reason == RejectReason.AlgNone ? null : $"refused as {refused.Reason}";
                }
            }).ConfigureAwait(false);

            // THE ALLOW-LIST REALLY COMES FROM DISCOVERY. An issuer publishing only RS256 must
            // refuse the honest EdDSA token, on the allow-list and not on the signature. Without
            // this, replacing the discovered list with a hard-coded superset would pass every other
            // check here, and the claim that the issuer decides would be decoration.
            _advertisedAlgorithms = """["RS256"]""";
            await CheckAsync("an algorithm the issuer does not publish is refused on the allow-list", async () =>
            {
                try
                {
                    await Sample.VerifyAsync(http, simpleBase, "cli_sample", token, now).ConfigureAwait(false);
                    return "it verified";
                }
                catch (VerifyException refused)
                {
                    return refused.Reason == RejectReason.AlgNotAllowed ? null : $"refused as {refused.Reason}";
                }
            }).ConfigureAwait(false);
            _advertisedAlgorithms = """["EdDSA"]""";

            // Discovery naming a different issuer must be refused: otherwise pointing the sample at
            // any URL yields a document naming an attacker-chosen issuer and a key set to match.
            _advertisedIssuer = "https://attacker.example";
            await CheckAsync("discovery naming a different issuer is refused", async () =>
            {
                try
                {
                    await Sample.VerifyAsync(http, simpleBase, "cli_sample", token, now).ConfigureAwait(false);
                    return "it verified";
                }
                catch (InvalidOperationException)
                {
                    return null;
                }
            }).ConfigureAwait(false);
            _advertisedIssuer = simpleBase;

            // The document ceiling is REAL, not a length check after the fact: the body is read in
            // bounded chunks and refused the moment it passes the limit. Measured here because a
            // bound nothing ever exceeds is indistinguishable from a bound that does not work.
            _oversizeJwks = true;
            await CheckAsync("an oversized key set is refused rather than buffered", async () =>
            {
                try
                {
                    await Sample.VerifyAsync(http, simpleBase, "cli_sample", token, now).ConfigureAwait(false);
                    return "it verified";
                }
                catch (HttpRequestException expected)
                {
                    return expected.Message.Contains("more than", StringComparison.Ordinal) ? null : expected.Message;
                }
            }).ConfigureAwait(false);
            _oversizeJwks = false;

            // A redirect on discovery is an invitation to fetch someone else's keys. The redirect
            // target names the CORRECT issuer and points at a DIFFERENT key set, so the issuer
            // check cannot save us here: only the decision not to follow it can.
            _redirectDiscovery = true;
            await CheckAsync("a redirect on discovery is not followed", async () =>
            {
                try
                {
                    await Sample.VerifyAsync(http, simpleBase, "cli_sample", token, now).ConfigureAwait(false);
                    return "it verified";
                }
                catch (HttpRequestException expected)
                {
                    return expected.Message.Contains("302", StringComparison.Ordinal) ? null : expected.Message;
                }
            }).ConfigureAwait(false);
            _redirectDiscovery = false;

            // Plaintext off the loopback interface is refused before any request, so this needs no
            // network and cannot flake.
            await CheckAsync("plaintext discovery off loopback is refused", async () =>
            {
                try
                {
                    await Sample.VerifyAsync(http, "http://issuer.example", "cli_sample", token, now).ConfigureAwait(false);
                    return "it verified";
                }
                catch (InvalidOperationException)
                {
                    return null;
                }
            }).ConfigureAwait(false);

            if (_checked < 8)
            {
                Failures.Add($"only {_checked} checks ran; this harness is its list");
            }
        }
        finally
        {
            await stopping.CancelAsync().ConfigureAwait(false);
            listener.Stop();
            // The loop returns on its own once the listener stops; awaiting it here means a real
            // fault inside the server still surfaces rather than being swallowed by the finally.
            await serving.ConfigureAwait(false);
        }

        if (Failures.Count > 0)
        {
            Console.Error.WriteLine("FAIL: the .NET sample does not hold up end to end");
            Failures.ForEach(failure => Console.Error.WriteLine("  - " + failure));
            return 1;
        }
        Console.WriteLine($"dotnet sample harness: {_checked} end-to-end checks against a live issuer OK");
        return 0;
    }

    private static async Task ServeAsync(
        HttpListener listener, string simpleBase, string x, string elsewhereX, CancellationToken token)
    {
        while (!token.IsCancellationRequested)
        {
            HttpListenerContext context;
            try
            {
                context = await listener.GetContextAsync().ConfigureAwait(false);
            }
#pragma warning disable CA1031 // shutdown, not a failure: see below
            catch (Exception)
#pragma warning restore CA1031
            {
                // Stopping the listener is HOW this loop ends, and the exception it produces
                // differs by platform (HttpListenerException, ObjectDisposedException, and an
                // InvalidOperationException on some runtimes). Enumerating them would be a list
                // that goes stale on the next runtime; what actually distinguishes shutdown from
                // a real fault is whether we asked it to stop.
                if (token.IsCancellationRequested || !listener.IsListening)
                {
                    return;
                }
                throw;
            }
            string path = context.Request.Url!.AbsolutePath;
            string body;
            switch (path)
            {
                case "/.well-known/openid-configuration" when _redirectDiscovery:
                    context.Response.StatusCode = 302;
                    context.Response.Headers.Add("location", simpleBase + "/elsewhere-discovery");
                    context.Response.Close();
                    continue;
                case "/.well-known/openid-configuration":
                    body = $$"""
                        {"issuer":"{{_advertisedIssuer}}","jwks_uri":"{{simpleBase}}{{(_oversizeJwks ? "/huge-jwks" : "/jwks")}}",
                         "id_token_signing_alg_values_supported":{{_advertisedAlgorithms}}}
                        """;
                    break;
                case "/jwks":
                    body = $$"""{"keys":[{"kty":"OKP","crv":"Ed25519","x":"{{x}}","kid":"sample-1"}]}""";
                    break;
                // Two megabytes of valid JSON, over the sample's one-megabyte ceiling.
                case "/huge-jwks":
                    body = $$"""{"keys":[],"padding":"{{new string('A', 2 << 20)}}"}""";
                    break;
                // The redirect target: the RIGHT issuer, a DIFFERENT key set.
                case "/elsewhere-discovery":
                    body = $$"""
                        {"issuer":"{{simpleBase}}","jwks_uri":"{{simpleBase}}/elsewhere-jwks",
                         "id_token_signing_alg_values_supported":["EdDSA"]}
                        """;
                    break;
                case "/elsewhere-jwks":
                    body = $$"""{"keys":[{"kty":"OKP","crv":"Ed25519","x":"{{elsewhereX}}","kid":"sample-1"}]}""";
                    break;
                default:
                    context.Response.StatusCode = 404;
                    context.Response.Close();
                    continue;
            }
            byte[] bytes = Encoding.UTF8.GetBytes(body);
            context.Response.ContentType = "application/json";
            context.Response.ContentLength64 = bytes.Length;
            await context.Response.OutputStream.WriteAsync(bytes, token).ConfigureAwait(false);
            context.Response.Close();
        }
    }

    /// <summary>
    /// A port nothing is listening on.
    /// </summary>
    /// <remarks>
    /// HttpListener has no "port 0" mode, so a socket is bound to pick one and closed again. There
    /// is a race in principle; on a loopback interface in a test run it has never mattered, and the
    /// alternative is a hard-coded port that collides with whatever else the machine is doing.
    /// </remarks>
    private static int FreePort()
    {
        using TcpListener probe = new(IPAddress.Loopback, 0);
        probe.Start();
        int port = ((IPEndPoint)probe.LocalEndpoint).Port;
        probe.Stop();
        return port;
    }

    private static async Task CheckAsync(string what, Func<Task<string?>> check)
    {
        _checked++;
        try
        {
            string? problem = await check().ConfigureAwait(false);
            if (problem is not null)
            {
                Failures.Add($"{what} -- {problem}");
            }
        }
#pragma warning disable CA1031 // catching everything is the ASSERTION here, not an oversight
        catch (Exception unexpected)
#pragma warning restore CA1031
        {
            Failures.Add($"{what} -- threw {unexpected.GetType().Name}: {unexpected.Message}");
        }
    }
}
