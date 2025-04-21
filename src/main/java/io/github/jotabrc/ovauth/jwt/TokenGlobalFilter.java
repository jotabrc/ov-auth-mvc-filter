package io.github.jotabrc.ovauth.jwt;

import io.github.jotabrc.ovauth.config.PropertiesWhitelistLoaderImpl;
import io.github.jotabrc.ovauth.header.Header;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class TokenGlobalFilter extends OncePerRequestFilter {

    @Deprecated
    private static final String[] PATH_WHITELIST = {
            "/v3/api-docs/",
            "/v3/api-docs-user/",
            "/v3/api-docs-product/",
            "/v3/api-docs-inventory/",
            "/v3/api-docs-order/",
            "/swagger-resources",
            "/swagger-resources/",
            "/configuration/ui",
            "/configuration/security",
            "/swagger-ui.html",
            "/swagger-ui/",
            "/swagger-user/",
            "/swagger-product/",
            "/swagger-inventory/",
            "/swagger-order/",
            "/webjars/",
            "/h2-console",
            "/h2-console/",
            "/h2-console-user",
            "/h2-console-inventory",
            "/h2-console-order"
    };

    private static final String[] WHITELIST = PropertiesWhitelistLoaderImpl.WHITELIST.values().toArray(new String[0]);

    /**
     * Validate headers and tokens.
     *
     * @param request     Received request to be checked.
     * @param response    Response to be returned.
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        if (whitelistCheck(request, response, filterChain)) return;
        if (validateXSecureToken(request, response)) return;

        validateAuthorizationHeader(request, response, filterChain);
    }

    private boolean whitelistCheck(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String path = request.getRequestURI();

        if (Arrays.stream(WHITELIST).anyMatch(path::startsWith)) {
            filterChain.doFilter(request, response);
            return true;
        }
        return false;
    }

    private List<SimpleGrantedAuthority> authorities(List<String> roles) {
        return roles.stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    private boolean validateXSecureToken(HttpServletRequest request, HttpServletResponse response) {
        String xSecureToken = request.getHeader(Header.X_SECURE_TOKEN.getHeader());

        if (xSecureToken != null && !xSecureToken.isEmpty()) {
            try {
                xSecureToken = xSecureToken.substring(7).trim();
                TokenObject tokenObject = TokenCreator.decode(xSecureToken, TokenConfig.PREFIX, TokenConfig.KEY);
                Date currentDate = new Date(System.currentTimeMillis());
                if (
                        !tokenObject.getSubject().equals("GATEWAY") &&
                                tokenObject.getRoles().stream().noneMatch(r -> r.equals("SYSTEM")) &&
                                tokenObject.getExpiration().after(currentDate)
                ) {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    return true;
                }
            } catch (SignatureException e) {
                throw new RuntimeException(e);
            }
        } else {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return true;
        }
        return false;
    }

    private void validateAuthorizationHeader(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        String token = request.getHeader(Header.HEADER_AUTHORIZATION.getHeader());
        try {
            if (token != null && !token.isEmpty()) {
                token = token.substring(7).trim();
                TokenObject tokenObject = TokenCreator.decode(token, TokenConfig.PREFIX, TokenConfig.KEY);

                List<SimpleGrantedAuthority> authorities = authorities(tokenObject.getRoles());

                UsernamePasswordAuthenticationToken userToken =
                        new UsernamePasswordAuthenticationToken(
                                tokenObject.getSubject(),
                                null,
                                authorities);

                SecurityContextHolder.getContext().setAuthentication(userToken);

            } else {
                SecurityContextHolder.clearContext();
            }
            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException | UnsupportedJwtException | MalformedJwtException | SignatureException e) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
        }
    }
}
