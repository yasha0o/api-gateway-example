package ru.examples.test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> {
                    requests.requestMatchers("/swagger-ui/**",
                            "/*/api-docs/**").permitAll();
                    requests.anyRequest().authenticated();
                })
                .oauth2ResourceServer(oauth2ResourceServer -> oauth2ResourceServer.jwt(Customizer.withDefaults()));
        return http.build();
    }
}
