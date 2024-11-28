package com.alibou.keycloak;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthConverter jwtAuthConverter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf()
                    .disable()
                .authorizeHttpRequests()
                    .anyRequest()
                        .authenticated();
//        Indique à Spring Security que l'application utilise OAuth2 comme mécanisme
//        d'authentification, avec des JWT (JSON Web Tokens).
        http
                .oauth2ResourceServer()
                    .jwt()
                        .jwtAuthenticationConverter(jwtAuthConverter);
//        Le mode STATELESS signifie que Spring Security n'utilise pas de sessions côté
//        serveur pour stocker des informations sur les utilisateurs authentifiés.
        http
                .sessionManagement()
                    .sessionCreationPolicy(STATELESS);

        return http.build();
    }
}
