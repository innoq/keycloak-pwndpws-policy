package com.innoq.keycloak.policy;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Formatter;

import static java.net.HttpURLConnection.HTTP_OK;
import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.Locale.ENGLISH;

final class PwndPwsClient {

    private static final MessageDigest sha1;

    static {
        try {
            sha1 = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to get instance for SHA-1", e);
        }
    }

    public int numberOfBreachesIncluding(String password) {
        final String hash = sha1Hex(password);

        final String prefix = hash.substring(0, 5);

        try {
            final URL url = new URL("https://api.pwnedpasswords.com/range/" + prefix);

            final HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.connect();

            if (connection.getResponseCode() != HTTP_OK) {
                throw new IllegalArgumentException("Pwnd pws API error: " + connection.getResponseCode() + " " + connection.getResponseMessage());
            }

            final String suffix = hash.substring(5);
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream(), UTF_8))) {
                return reader.lines()
                        .filter(line -> line.startsWith(suffix))
                        .findAny()
                        .map(line -> line.split(":"))
                        .map(result -> result[1])
                        .map(Integer::parseInt)
                        .orElse(0);
            }
        } catch (Exception e) {
            throw new IllegalArgumentException("Unable to call pwnd pws API", e);
        }
    }

    private String sha1Hex(String text) {
        return byteToHex(sha1.digest(text.getBytes(UTF_8)));
    }

    private static String byteToHex(final byte[] hash) {
        try (Formatter formatter = new Formatter()) {
            for (byte b : hash) {
                formatter.format("%02x", b);
            }
            return formatter.toString().toUpperCase(ENGLISH);
        }
    }
}
