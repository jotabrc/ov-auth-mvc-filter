package io.github.jotabrc.ovauth.config;

import org.springframework.core.io.Resource;

public interface PropertiesWhitelistLoader {

    void loadProperties(final Resource resource);
}
