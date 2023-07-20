package com.arturbarth.springboot3keycloakmultitenant.config;

import com.nimbusds.jwt.JWTParser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.convert.converter.Converter;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Component
@Slf4j
public class JwtAuthConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private final JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter =
            new JwtGrantedAuthoritiesConverter();

    @Value("${jwt.auth.converter.principle-attribute}")
    private String principleAttribute;
    @Value("${jwt.auth.converter.resource-id}")
    private String resourceId;

    private static final String AUTH_HEADER = "Authorization";
    private static final String TOKEN_PREFIX = "bearer";
    private static final String REALMS_PATH = "realms/";
    private static final String SECRET = "secret";

    @Override
    public AbstractAuthenticationToken convert(@NonNull Jwt jwt) {
        String token = jwt.getTokenValue();
        log.info("token: {}", token);
        var realm = getRealmByToken(jwt.getTokenValue());
        log.info("realm: {}", realm);


        Collection<GrantedAuthority> authorities = Stream.concat(
                jwtGrantedAuthoritiesConverter.convert(jwt).stream(),
                extractResourceRoles(jwt).stream()
        ).collect(Collectors.toSet());

        return new JwtAuthenticationToken(
                jwt,
                authorities,
                getPrincipleClaimName(jwt)
        );
    }

    private Collection<? extends GrantedAuthority> extractResourceRoles(Jwt jwt) {
        Map<String, Object> resourceAccess;
        Map<String, Object> resource;
        Collection<String> resourceRoles;
        if (jwt.getClaim("resource_access") == null) {
            return Set.of();
        }
        resourceAccess = jwt.getClaim("resource_access");

        if (resourceAccess.get(resourceId) == null) {
            return Set.of();
        }
        resource = (Map<String, Object>) resourceAccess.get(resourceId);

        resourceRoles = (Collection<String>) resource.get("roles");
        return resourceRoles
                .stream()
                .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                .collect(Collectors.toSet());
    }


    private String getRealmByToken(String authorization){
        if (authorization == null) return "";
        try {
            return getIssuer(authorization);
        }catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    private static String extractTokenFromHeader(String authHeader){
        if (!authHeader.toLowerCase().startsWith(TOKEN_PREFIX)) {
            throw new RuntimeException();
        }
        if(authHeader.length() <= (TOKEN_PREFIX.length() + 1)){
            throw new RuntimeException();
        }
        return authHeader.substring(TOKEN_PREFIX.length() + 1);
    }


    private String getIssuer(String authorization) throws Exception {
        var token = authorization;
        var jwt = JWTParser.parse(token);
        var issuer = jwt.getJWTClaimsSet().getIssuer();
        if (issuer == null || !issuer.contains(REALMS_PATH)) {
            throw new RuntimeException();
        }
        return issuer.substring(issuer.lastIndexOf("/") + 1);
    }

    private String getPrincipleClaimName(Jwt jwt) {
        String claimName = JwtClaimNames.SUB;
        if (principleAttribute != null) {
            claimName = principleAttribute;
        }
        return jwt.getClaim(claimName);
    }


}
