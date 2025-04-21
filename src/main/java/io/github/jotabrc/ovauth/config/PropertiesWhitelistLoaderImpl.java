package io.github.jotabrc.ovauth.config;

import jakarta.annotation.PostConstruct;
import org.springframework.stereotype.Component;

import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Component
public class PropertiesWhitelistLoaderImpl implements PropertiesWhitelistLoader {

    public static Map<String, String> whitelist = new HashMap<>();

    @PostConstruct
    public void init() {
        loadProperties();
    }

    @Override
    public void loadProperties() {
        loadProperties("ov-auth.properties");
    }

    @Override
    public void loadProperties(String path) {
        try (FileInputStream stream = new FileInputStream(path)) {
            Properties properties = new Properties();
            properties.load(stream);
            properties.forEach((k,v) -> whitelist.put(k.toString(), v.toString()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
