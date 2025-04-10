package io.github.jotabrc.ovauth.header;

import org.springframework.security.access.AccessDeniedException;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class SecurityHeader {

    /**
     * Creates Token String using environment variable HEADER_KEY.
     * @param data Data to be encoded.
     * @return Token String.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public static String create(String data) throws NoSuchAlgorithmException, InvalidKeyException {
        String secretKey = System.getenv("HEADER_KEY");
        final String algorithm = "HmacSHA256";
        Mac mac = Mac.getInstance(algorithm);

        SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), algorithm);
        mac.init(secretKeySpec);

        byte[] hmacBytes = mac.doFinal(data.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    /**
     * Validates with encoded data received is valid.
     * @param data To be encoded and compared with encodedHeader.
     * @param encodedHeader Encoded data received.
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     * @throws AccessDeniedException
     */
    public static void compare(String data, String encodedHeader) throws NoSuchAlgorithmException, InvalidKeyException, AccessDeniedException {
        String encodedData = create(data);
        if (encodedData.equals(encodedHeader)) return;

        throw new AccessDeniedException("Access denied");
    }
}
