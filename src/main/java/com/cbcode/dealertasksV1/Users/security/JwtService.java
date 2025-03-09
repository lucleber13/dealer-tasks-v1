package com.cbcode.dealertasksV1.Users.security;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Map;
import java.util.function.Function;

public interface JwtService {

    String generateJwtToken(UserDetails userDetails);

    String getUsernameFromToken(String token);

    boolean validateToken(String token, UserDetails userDetails);

    boolean isTokenExpired(String token);

    String generateRefreshToken(Map<String, Object> claims, UserDetails userDetails);

   String getTokenType(String token);
}
