package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.Users.security.JwtService;
import com.cbcode.dealertasksV1.Users.security.SecurityUserService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final Logger logger = LoggerFactory.getLogger(JwtAuthFilter.class);
    private final JwtService jwtService;
    private final SecurityUserService userSecurityService;

    public JwtAuthFilter(JwtService jwtService, SecurityUserService userSecurityService) {
        this.jwtService = jwtService;
        this.userSecurityService = userSecurityService;
    }

    /**
     * Method to intercept requests and validate JWT tokens.
     * If a valid token is found, the user is authenticated and added to the security context.
     * If the token is invalid, the security context is cleared.
     * If no token is found, the request is passed to the next filter in the chain.
     *
     * @param request     - The request object.
     * @param response    - The response object.
     * @param filterChain - The filter chain object.
     * @throws ServletException - If an error occurs during the filter process.
     * @throws IOException      - If an error occurs during the filter process.
     */
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain) throws ServletException, IOException {
        final String jwt = extractJwtFromRequest(request);
        if (jwt == null) {
            logger.debug("No valid JWT token found in request headers");
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String userEmail = jwtService.getUsernameFromToken(jwt);
            if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                UserDetails userDetails = userSecurityService.getUserDetailsService().loadUserByUsername(userEmail);
                if (jwtService.validateToken(jwt, userDetails)) {
                    UsernamePasswordAuthenticationToken authToken =
                            new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                    logger.info("Authenticated user: {}", userEmail);
                }
            }
        } catch (Exception e) {
            logger.error("Failed to authenticate user with JWT: {}", e.getMessage(), e);
            SecurityContextHolder.clearContext();
        }
        filterChain.doFilter(request, response);
    }

    private String extractJwtFromRequest(HttpServletRequest request) {
        final String authorizationHeader = request.getHeader("Authorization");
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }
}
