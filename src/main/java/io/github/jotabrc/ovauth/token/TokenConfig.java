package io.github.jotabrc.ovauth.token;

import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * Token Configuration class.
 */
@Setter
@Configuration
@ConfigurationProperties(prefix = "security.config")
public class TokenConfig {
    public static String PREFIX = "Bearer";
    public static String KEY = System.getenv("SECRET_KEY");
    public static Long EXPIRATION = 3600000L;
}
