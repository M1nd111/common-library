package com.example.starter.security;

import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.SecurityException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.List;

@Component
public class JwtValidator {

    private final SecretKey secretKey;

    public JwtValidator(@Value("${jwt.secret}") String secret) {
        secretKey = Keys.hmacShaKeyFor(secret.getBytes());
    }

    public Claims validateToken(String token) {
        try {
            return Jwts
                .parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
        } catch (SecurityException e) {
            throw new SecurityException("Invalid JWT signature");
        } catch (MalformedJwtException e) {
            throw new MalformedJwtException("Invalid JWT token");
        } catch (ExpiredJwtException e) {
            throw new JwtException("Expired JWT token");
        } catch (UnsupportedJwtException e) {
            throw new JwtException("Unsupported JWT token");
        } catch (IllegalArgumentException e) {
            throw new JwtException("Token is empty");
        }
    }

    public List<SimpleGrantedAuthority> getAuthorities(Claims claims) {
        List<String> roles = claims.get("roles", List.class);
        return roles.stream()
            .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
            .toList();
    }

}
