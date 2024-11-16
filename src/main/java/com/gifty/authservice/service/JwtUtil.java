package com.gifty.authservice.service;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {

    private final SecretKey accessTokenKey;
    private final SecretKey refreshTokenKey;

    private final long accessTokenValidity;
    private final long refreshTokenValidity;

    public JwtUtil(
            @Value("${jwt.secret.access}") String accessSecret,
            @Value("${jwt.secret.refresh}") String refreshSecret,
            @Value("${jwt.access.token.validity}") long accessTokenValidity,
            @Value("${jwt.refresh.token.validity}") long refreshTokenValidity
    ) {
        this.accessTokenKey = Keys.hmacShaKeyFor(accessSecret.getBytes());
        this.refreshTokenKey = Keys.hmacShaKeyFor(refreshSecret.getBytes());
        this.accessTokenValidity = accessTokenValidity;
        this.refreshTokenValidity = refreshTokenValidity;
    }

    public String generateAccessToken(String username, Map<String, Object> claims) {
        // Mutable bir Map oluşturun
        Map<String, Object> mutableClaims = new HashMap<>();
        if (claims != null) {
            mutableClaims.putAll(claims); // Immutable map'i mutable bir kopyaya alın
        }

        mutableClaims.put("type", "access"); // Token türü: Access
        return Jwts.builder()
                .setClaims(mutableClaims) // Mutable map'i kullanın
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + accessTokenValidity))
                .signWith(accessTokenKey)
                .compact();
    }

    public String generateRefreshToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshTokenValidity))
                .signWith(refreshTokenKey)
                .claim("type", "refresh") // Refresh token olduğunu belirtiyoruz
                .compact();
    }

    public boolean validateToken(String token, boolean isAccessToken) {
        try {
            SecretKey key = isAccessToken ? accessTokenKey : refreshTokenKey;
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }

    public String getUsernameFromToken(String token, boolean isAccessToken) {
        SecretKey key = isAccessToken ? accessTokenKey : refreshTokenKey;
        return Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token).getBody().getSubject();
    }

    public boolean isTokenExpired(String token, boolean isAccessToken) {
        try {
            SecretKey key = isAccessToken ? accessTokenKey : refreshTokenKey;
            Claims claims = Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
        } catch (JwtException | IllegalArgumentException e) {
            throw new RuntimeException("Invalid token format."); // İstersen custom exception kullanabilirsin
        }
    }

    public Claims getClaimsFromToken(String token, boolean isAccessToken) {
        SecretKey key = isAccessToken ? accessTokenKey : refreshTokenKey;
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

}
