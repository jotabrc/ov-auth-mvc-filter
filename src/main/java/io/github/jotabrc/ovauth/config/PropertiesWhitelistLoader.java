package io.github.jotabrc.ovauth.config;

public interface PropertiesWhitelistLoader {

    void loadProperties();
    void loadProperties(final String path);
}
