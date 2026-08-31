// SPDX-License-Identifier: MIT OR Apache-2.0
package dev.ironauth.verify;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * A minimal JSON reader (issue #118).
 *
 * <p>Java has no JSON parser in the standard library, and this artifact's whole promise is that
 * verifying an IronAuth token needs <em>no extra user dependencies</em>. Pulling in Jackson to
 * read a two-field JWT header would break that promise for the sake of forty lines.
 *
 * <p>It reads exactly what a JWT header, a JWT claim set, and a JWK Set contain: objects, arrays,
 * strings, numbers, booleans and null. It is not a general-purpose parser and does not try to be
 * -- there is no streaming, no comment handling, no big-number precision beyond {@code double},
 * and a trailing comma is an error rather than a kindness.
 *
 * <p><strong>It is not a security boundary.</strong> It parses a token's segments <em>before</em>
 * the signature is checked, so everything it returns is attacker-controlled until
 * {@link IronAuthVerifier} says otherwise. What protects the verifier is that nothing it returns
 * selects a key or an algorithm: those come from the caller's policy.
 */
final class Json {
    private final String text;
    private int at;

    private Json(String text) {
        this.text = text;
    }

    /** Parse a complete document. Trailing content is an error, not ignored. */
    static Object parse(String text) {
        Json reader = new Json(text);
        reader.skipWhitespace();
        Object value = reader.readValue();
        reader.skipWhitespace();
        if (reader.at != text.length()) {
            throw new IllegalArgumentException("trailing content at " + reader.at);
        }
        return value;
    }

    private Object readValue() {
        if (at >= text.length()) {
            throw new IllegalArgumentException("unexpected end of input");
        }
        char c = text.charAt(at);
        switch (c) {
            case '{':
                return readObject();
            case '[':
                return readArray();
            case '"':
                return readString();
            case 't':
                expect("true");
                return Boolean.TRUE;
            case 'f':
                expect("false");
                return Boolean.FALSE;
            case 'n':
                expect("null");
                return null;
            default:
                return readNumber();
        }
    }

    private Map<String, Object> readObject() {
        // LinkedHashMap, so member order is preserved. Nothing here depends on it, but a parser
        // that reorders makes a diff of two parsed documents unreadable.
        Map<String, Object> members = new LinkedHashMap<>();
        at++; // '{'
        skipWhitespace();
        if (peek() == '}') {
            at++;
            return members;
        }
        while (true) {
            skipWhitespace();
            String name = readString();
            skipWhitespace();
            if (peek() != ':') {
                throw new IllegalArgumentException("expected ':' at " + at);
            }
            at++;
            skipWhitespace();
            members.put(name, readValue());
            skipWhitespace();
            char next = peek();
            at++;
            if (next == '}') {
                return members;
            }
            if (next != ',') {
                throw new IllegalArgumentException("expected ',' or '}' at " + (at - 1));
            }
        }
    }

    private List<Object> readArray() {
        List<Object> items = new ArrayList<>();
        at++; // '['
        skipWhitespace();
        if (peek() == ']') {
            at++;
            return items;
        }
        while (true) {
            skipWhitespace();
            items.add(readValue());
            skipWhitespace();
            char next = peek();
            at++;
            if (next == ']') {
                return items;
            }
            if (next != ',') {
                throw new IllegalArgumentException("expected ',' or ']' at " + (at - 1));
            }
        }
    }

    private String readString() {
        if (peek() != '"') {
            throw new IllegalArgumentException("expected a string at " + at);
        }
        at++;
        StringBuilder out = new StringBuilder();
        while (true) {
            if (at >= text.length()) {
                throw new IllegalArgumentException("unterminated string");
            }
            char c = text.charAt(at++);
            if (c == '"') {
                return out.toString();
            }
            if (c != '\\') {
                out.append(c);
                continue;
            }
            char escape = text.charAt(at++);
            switch (escape) {
                case '"': out.append('"'); break;
                case '\\': out.append('\\'); break;
                case '/': out.append('/'); break;
                case 'b': out.append('\b'); break;
                case 'f': out.append('\f'); break;
                case 'n': out.append('\n'); break;
                case 'r': out.append('\r'); break;
                case 't': out.append('\t'); break;
                case 'u':
                    out.append((char) Integer.parseInt(text.substring(at, at + 4), 16));
                    at += 4;
                    break;
                default:
                    throw new IllegalArgumentException("bad escape \\" + escape);
            }
        }
    }

    private Double readNumber() {
        int start = at;
        while (at < text.length() && "-+.eE0123456789".indexOf(text.charAt(at)) >= 0) {
            at++;
        }
        if (start == at) {
            throw new IllegalArgumentException("expected a value at " + at);
        }
        return Double.valueOf(text.substring(start, at));
    }

    private void expect(String literal) {
        if (!text.startsWith(literal, at)) {
            throw new IllegalArgumentException("expected " + literal + " at " + at);
        }
        at += literal.length();
    }

    private char peek() {
        if (at >= text.length()) {
            throw new IllegalArgumentException("unexpected end of input");
        }
        return text.charAt(at);
    }

    private void skipWhitespace() {
        while (at < text.length() && Character.isWhitespace(text.charAt(at))) {
            at++;
        }
    }
}
