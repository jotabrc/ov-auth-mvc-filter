package io.github.jotabrc.ovauth.config;

import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

@Component
public class PropertiesWhitelistLoaderImpl implements PropertiesWhitelistLoader {

    @Value("classpath:ov-auth.properties")
    private Resource resource;

    public static Map<String, String> WHITELIST = new HashMap<>();

    @PostConstruct
    public void init() {
        loadProperties(resource);
    }

    @Override
    public void loadProperties(Resource resource) {
        try (InputStream stream = resource.getInputStream()) {
            Properties properties = new Properties();
            properties.load(stream);
            properties.forEach((k,v) -> WHITELIST.put(k.toString(), v.toString()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }
}
