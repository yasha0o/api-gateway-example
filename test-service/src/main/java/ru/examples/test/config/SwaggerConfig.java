package ru.examples.test.config;

import io.swagger.v3.oas.models.servers.Server;
import io.swagger.v3.oas.models.OpenAPI;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class SwaggerConfig {

    @Bean
    public OpenAPI openAPI(@Value("${springdoc.service-url}") String serviceUrl) {
        return new OpenAPI().addServersItem(new Server().url(serviceUrl));
    }
}
