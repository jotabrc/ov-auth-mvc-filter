package io.github.jotabrc.ovauth.config;

import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Component
public class PropertiesWhitelistLoaderImpl implements PropertiesWhitelistLoader {

    public static Map<String, String> WHITELIST = new HashMap<>();

    @Override
    public void loadProperties() {
        loadProperties("ov-auth.properties");
    }

    @Override
    public void loadProperties(String path) {
        try (InputStream stream = getClass().getClassLoader().getResourceAsStream(path)) {
            Properties properties = new Properties();
            properties.load(stream);
            properties.forEach((k,v) -> WHITELIST.put(k.toString(), v.toString()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
