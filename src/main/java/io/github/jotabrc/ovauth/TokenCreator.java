package io.github.jotabrc.ovauth;

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
    public static final String HEADER_AUTHORIZATION = "Authorization";
    public static final String HEADER_SECURE_DATA = "X-Secure-Data";
    public static final String HEADER_SECURE_ORIGIN = "X-Secure-Origin";
    public static final String ROLES_AUTHORITIES = "authorities";

    /**
     * Creates JWT Bearer token.
     * @param prefix Token prefix defined in TokenConfig class.
     * @param key Secret Secure key.
     * @param tokenObject Object with token information to use in JWT creation.
     * @return
     */
    public static String create(String prefix, String key, TokenObject tokenObject) {

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKey signingKey = new SecretKeySpec(keyBytes, "HmacSHA512");

        String token = Jwts.builder()
                .subject(tokenObject.getSubject())
                .issuedAt(tokenObject.getIssuedAt())
                .expiration(tokenObject.getExpiration())
                .claim(ROLES_AUTHORITIES, checkRoles(tokenObject.getRoles()))
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
    public static TokenObject create(String token, String prefix, String key)
            throws ExpiredJwtException, UnsupportedJwtException, MalformedJwtException, SignatureException {

        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        SecretKey signingKey = new SecretKeySpec(keyBytes, "HmacSHA512");

        TokenObject object = new TokenObject();
        token = token.replace(prefix, "");

        var claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        object.setSubject(claims.getSubject());
        object.setExpiration(claims.getExpiration());
        object.setIssuedAt(claims.getIssuedAt());
        object.setRoles((List) claims.get(ROLES_AUTHORITIES));
        return object;

    }

    private static List<String> checkRoles(List<String> roles) {
        return roles.stream().map(s -> "ROLE_".concat(s.replaceAll("ROLE_",""))).collect(Collectors.toList());
    }
}
