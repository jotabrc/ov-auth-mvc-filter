package io.github.jotabrc.ovauth;

import org.springframework.security.access.AccessDeniedException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class HeaderSecurity {

    /**
     * Encoded received header data for matching with encoded header.
     * @param data X-Secure-Data header received with JWT Token.
     * @param header X-Secure-Data header received with JWT Token.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws AccessDeniedException
     */
    public static void compare(String data, String header) throws NoSuchAlgorithmException, InvalidKeyException, AccessDeniedException {
        String secretKey = System.getenv("HEADER_KEY");
        final String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);

        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);
        mac.init(secretKeySpec);

        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        String encodedHeader = Base64.getEncoder().encodeToString(hmacBytes);
        if (encodedHeader.equals(header)) return;

        throw new AccessDeniedException("Access denied");
    }
}
