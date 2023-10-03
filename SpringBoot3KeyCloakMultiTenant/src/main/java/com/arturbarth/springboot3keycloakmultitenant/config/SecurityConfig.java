package com.arturbarth.springboot3keycloakmultitenant.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
        JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(authenticationManagers::get);

        List<String> issuers = new ArrayList<>();
        issuers.add("http://localhost:8080/realms/tenant1");
        issuers.add("http://localhost:8080/realms/tenant2");
        issuers.add("http://localhost:8080/realms/tenant3");
        issuers.forEach(issuer -> addManager(authenticationManagers, issuer));

        return http
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().authenticated())
                .oauth2ResourceServer(oauth2 -> oauth2
                        .authenticationManagerResolver(authenticationManagerResolver))
                .build();
    }

    private void addManager(Map<String, AuthenticationManager> authenticationManagers, String issuer) {
        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(JwtDecoders.fromIssuerLocation(issuer));
        authenticationProvider.setJwtAuthenticationConverter(jwtAuthConverter);
        authenticationManagers.put(issuer, authenticationProvider::authenticate);
    }
}
