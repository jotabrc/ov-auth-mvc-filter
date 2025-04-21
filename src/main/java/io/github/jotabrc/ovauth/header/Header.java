package io.github.jotabrc.ovauth.header;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum Header {

    X_SECURE_DATA("X-Secure-Data"),
    X_SECURE_ORIGIN("X-Secure-Origin"),
    X_SECURE_TOKEN("X-Secure-Token"),
    HEADER_AUTHORIZATION("Authorization"),
    ROLES_AUTHORITIES("authorities");

    private final String header;
}
