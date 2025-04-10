package io.github.jotabrc.ovauth.token;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.Accessors;

import java.util.Date;
import java.util.List;

@Accessors(chain = true)
@Builder
@Getter
@Setter
public class TokenObject {
    private String subject;
    private Date issuedAt;
    private Date expiration;
    private List<String> roles;
}
