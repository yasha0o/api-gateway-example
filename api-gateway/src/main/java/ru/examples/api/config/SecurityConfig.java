package ru.examples.api.config;

import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.session.data.redis.config.annotation.web.http.EnableRedisIndexedHttpSession;
import org.springframework.web.client.RestClient;

import java.util.Optional;

@Slf4j
@Configuration
@EnableWebSecurity(debug = true)
@EnableMethodSecurity
@EnableRedisIndexedHttpSession
public class SecurityConfig {

    @Bean
    SecurityFilterChain clientSecurityFilterChain(HttpSecurity http,
                                                  ClientRegistrationRepository clientRegistrationRepository,
                                                  @Value("${app.main-page}") String mainPage,
                                                  @Value("${app.login-url}") String loginUrl) throws Exception {
        http.cors(Customizer.withDefaults()).csrf(AbstractHttpConfigurer::disable);
        http.oauth2Login(Customizer.withDefaults());
        http.oauth2Login(auth -> {
            auth.defaultSuccessUrl(mainPage);
        });
        http.logout(conf -> {
            val logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
            logoutSuccessHandler.setPostLogoutRedirectUri(loginUrl);
            conf.logoutSuccessHandler(logoutSuccessHandler);
            conf.invalidateHttpSession(true);
            conf.clearAuthentication(true);
            conf.addLogoutHandler((req, resp, auth) -> {
                Optional.ofNullable(req.getSession()).ifPresent(HttpSession::invalidate);
                SecurityContextHolder.clearContext();
            });
        });

        http.anonymous(AbstractHttpConfigurer::disable);
        http.authorizeHttpRequests(auth -> {
            auth.requestMatchers(
                    "/login/**",
                    "/logout",
                    "/oauth2/**",
                    "/swagger-ui/**",
                    "/*/api-docs/**").permitAll();
            auth.anyRequest().authenticated();
        });
        return http.build();
    }


    @Bean
    public RestClient.Builder restClient() {
        //логирование запросов, которые в итоге высылает cloud gateway mvc
        return RestClient.builder()
                .requestInterceptor((request, body, execution) -> {
                    log.info("Executing request: {} ({}): {}", request.getURI(), request.getMethod(), body);
                    return execution.execute(request, body);
                });
    }
}
