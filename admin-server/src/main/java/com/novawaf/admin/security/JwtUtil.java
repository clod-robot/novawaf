package com.novawaf.admin.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtUtil {
    private final SecretKey key;
    private final long expireMs;

    public JwtUtil(@Value("${nova.jwt.secret}") String secret,
                   @Value("${nova.jwt.expire-minutes}") long expireMinutes) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            // 补齐到 32 字节以满足 HS256
            byte[] pad = new byte[32];
            System.arraycopy(bytes, 0, pad, 0, Math.min(bytes.length, 32));
            bytes = pad;
        }
        this.key = Keys.hmacShaKeyFor(bytes);
        this.expireMs = expireMinutes * 60_000L;
    }

    public String create(Long userId, String username) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("uid", userId);
        claims.put("username", username);
        Date now = new Date();
        return Jwts.builder().claims(claims)
                .issuedAt(now).expiration(new Date(now.getTime() + expireMs))
                .signWith(key).compact();
    }

    public Claims parse(String token) {
        return Jwts.parser().verifyWith(key).build()
                .parseSignedClaims(token).getPayload();
    }
}
