package io.github.jotabrc.ovauth.jwt;

import io.github.jotabrc.ovauth.config.PropertiesWhitelistLoaderImpl;
import io.github.jotabrc.ovauth.header.Header;
import io.github.jotabrc.ovauth.token.SecurityHeader;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.InvalidKeyException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.Arrays;
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

    private static final String[] WHITELIST = PropertiesWhitelistLoaderImpl.whitelist.values().toArray(new String[0]);

    /**
     * Validate headers and tokens.
     * @param request Received request to be checked.
     * @param response Response to be returned.
     * @param filterChain
     * @throws ServletException
     * @throws IOException
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        if (Arrays.stream(WHITELIST).anyMatch(path::startsWith)) {
            filterChain.doFilter(request, response);
            return;
        }

        String headerData =  request.getHeader(Header.X_SECURE_DATA.getHeader());
        String headerOrigin =  request.getHeader(Header.X_SECURE_ORIGIN.getHeader());

        try {
            if (headerData != null && headerOrigin != null) {
                SecurityHeader.compare(headerData, headerOrigin);
            } else {
                throw new AccessDeniedException("Access denied");
            }
        } catch (NoSuchAlgorithmException | InvalidKeyException | AccessDeniedException |
                 java.security.InvalidKeyException e) {
            response.setStatus(HttpStatus.FORBIDDEN.value());
            return;
        }

        String token =  request.getHeader(Header.HEADER_AUTHORIZATION.getHeader());
        try {
            if(token != null && !token.isEmpty()) {
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

    private List<SimpleGrantedAuthority> authorities(List<String> roles){
        return roles.stream().map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }
}
