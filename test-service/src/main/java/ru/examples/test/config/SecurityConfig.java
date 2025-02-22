package ru.examples.test.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisIndexedHttpSession;

@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity
@EnableRedisIndexedHttpSession
public class SecurityConfig {

    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(requests -> {
            requests.anyRequest().authenticated();
        });
        http.sessionManagement(cfg -> cfg.sessionCreationPolicy(SessionCreationPolicy.NEVER));
        return http.build();
    }
}
