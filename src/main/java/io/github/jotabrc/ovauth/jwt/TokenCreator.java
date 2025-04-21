package io.github.jotabrc.ovauth.jwt;

import io.github.jotabrc.ovauth.header.Header;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.util.List;
import java.util.stream.Collectors;

public class TokenCreator {

    /**
     * Creates JWT Bearer token.
     * @param prefix Token prefix defined in TokenConfig class.
     * @param key Secret Secure key.
     * @param tokenObject Object with token information to use in JWT creation.
     * @return Token String.
     */
    public static String create(String prefix, String key, TokenObject tokenObject) {

        SecretKey signingKey = getSecretKey(key);

        String token = Jwts.builder()
                .subject(tokenObject.getSubject())
                .issuedAt(tokenObject.getIssuedAt())
                .expiration(tokenObject.getExpiration())
                .claim(Header.ROLES_AUTHORITIES.getHeader(), checkRoles(tokenObject.getRoles()))
                .signWith(signingKey)
                .compact();
        return prefix + " " + token;
    }

    /**
     * Decode received JWT token and return TokenObject details.
     * @param token Received JWT.
     * @param prefix Token prefix defined in TokenConfig class.
     * @param key Secret Secure key.
     * @return
     * @throws ExpiredJwtException
     * @throws UnsupportedJwtException
     * @throws MalformedJwtException
     * @throws SignatureException
     */
    public static TokenObject decode(String token, String prefix, String key)
            throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException {

        SecretKey signingKey = getSecretKey(key);

        token = token.replace(prefix, "");

        var claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        return TokenObject
                .builder()
                .subject(claims.getSubject())
                .expiration(claims.getExpiration())
                .issuedAt(claims.getIssuedAt())
                .roles((List<String>) claims.get(Header.ROLES_AUTHORITIES.getHeader()))
                .build();

    }

    private static List<String> checkRoles(List<String> roles) {
        return roles.stream().map(s -> "ROLE_".concat(s.replaceAll("ROLE_",""))).collect(Collectors.toList());
    }

    private static SecretKey getSecretKey(String key) {
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKey signingKey = new SecretKeySpec(keyBytes, "HmacSHA512");
        return signingKey;
    }
}
