// SPDX-License-Identifier: MIT OR Apache-2.0
namespace IronAuth.Verify;

/// <summary>Unpadded base64url, as RFC 7515 section 2 requires (issue #118).</summary>
/// <remarks>
/// Written out rather than taken from <c>System.Buffers.Text.Base64Url</c>, which arrived in
/// .NET 9: this artifact targets net8.0 so it is usable on the current LTS, and the eighteen
/// lines here are cheaper than a second target framework.
/// </remarks>
public static class Base64Url
{
    /// <summary>Decode one unpadded base64url string.</summary>
    /// <exception cref="FormatException">
    /// if the input is padded, uses the standard alphabet, or is not base64 at all. Padding is
    /// refused rather than tolerated: accepting it would mean two encodings of one token, which
    /// is how signature-stripping tricks start.
    /// </exception>
    public static byte[] Decode(string value)
    {
        ArgumentNullException.ThrowIfNull(value);
        foreach (char c in value)
        {
            bool allowed = c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_';
            if (!allowed)
            {
                throw new FormatException("not unpadded base64url");
            }
        }
        string padded = value.Replace('-', '+').Replace('_', '/');
        padded += (value.Length % 4) switch
        {
            2 => "==",
            3 => "=",
            0 => "",
            // A base64 group is never one character long; Convert would report this less clearly.
            _ => throw new FormatException("a base64url segment of invalid length"),
        };
        return Convert.FromBase64String(padded);
    }

    /// <summary>Encode bytes as unpadded base64url.</summary>
    public static string Encode(ReadOnlySpan<byte> bytes) =>
        Convert.ToBase64String(bytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
