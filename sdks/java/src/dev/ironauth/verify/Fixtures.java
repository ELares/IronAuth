// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.verify;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.Signature;
import java.security.interfaces.EdECPublicKey;
import java.util.Base64;

/**
 * Minting helpers shared by {@link SelfTest} and {@link SampleHarness} (issue #118).
 *
 * <p>These exist because both suites need to sign a token the shared corpus could not contain:
 * the corpus has no private key, so anything requiring a VALID signature over attacker-chosen
 * headers has to be minted here.
 */
final class Fixtures {

    private Fixtures() {}

    /** Mint a genuinely signed Ed25519 JWS over the given header and claims, verbatim. */
    static String mint(KeyPair pair, String header, String claims) throws Exception {
        String signingInput =
                b64(header.getBytes(StandardCharsets.UTF_8)) + "." + b64(claims.getBytes(StandardCharsets.UTF_8));
        Signature signer = Signature.getInstance("Ed25519");
        signer.initSign(pair.getPrivate());
        signer.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + b64(signer.sign());
    }

    /**
     * The inverse of {@link TrustedKey}'s Ed25519 decoding: 32-byte little-endian y with the
     * parity of x in the top bit of the last byte (RFC 8032 5.1.2).
     */
    static String encodeEd25519(EdECPublicKey key) {
        byte[] bigEndian = key.getPoint().getY().toByteArray();
        byte[] raw = new byte[32];
        for (int i = 0; i < 32 && i < bigEndian.length; i++) {
            // toByteArray is big-endian and may carry a leading sign byte, so index from the END.
            raw[i] = bigEndian[bigEndian.length - 1 - i];
        }
        if (key.getPoint().isXOdd()) {
            raw[31] |= (byte) 0x80;
        }
        return b64(raw);
    }

    static String b64(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
