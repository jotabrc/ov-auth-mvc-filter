package io.github.jotabrc.ovauth;

import lombok.Getter;
import lombok.Setter;

import java.util.Date;
import java.util.List;

@Getter
@Setter
public class TokenObject {
    private String subject;
    private Date issuedAt;
    private Date expiration;
    private List<String> roles;
}
