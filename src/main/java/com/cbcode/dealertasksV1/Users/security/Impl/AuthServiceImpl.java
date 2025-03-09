package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.ExceptionsConfig.InvalidTokenException;
import com.cbcode.dealertasksV1.ExceptionsConfig.TokenExpiredException;
import com.cbcode.dealertasksV1.ExceptionsConfig.UserNotFoundException;
import com.cbcode.dealertasksV1.Users.model.User;
import com.cbcode.dealertasksV1.Users.repository.UserRepository;
import com.cbcode.dealertasksV1.Users.security.AuthService;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.LoginRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.PasswordResetDto;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.RefreshTokenRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.UserDetailsValidations;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.JwtAuthResponse;
import com.cbcode.dealertasksV1.Users.security.JwtService;
import com.cbcode.dealertasksV1.Users.security.RateLimit;
import com.cbcode.dealertasksV1.Users.security.SecurityUserService;
import com.cbcode.dealertasksV1.Users.service.EmailService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final EmailService emailService;
    private final SecurityUserService securityUserService;
    private final UserDetailsValidations userDetailsValidations;

    public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager,
                           EmailService emailService, SecurityUserService securityUserService, UserDetailsValidations userDetailsValidations) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.emailService = emailService;
        this.securityUserService = securityUserService;
        this.userDetailsValidations = userDetailsValidations;
    }

    /**
     * Authenticates a user based on the provided login request and returns a JWT token response.
     * Assumes the login request has been validated during construction.
     * Authenticates the credentials using Spring Security and generates access and refresh tokens.
     *
     * @param loginRequest The validated request containing the user's email and password.
     * @return A JwtAuthResponse containing the generated access and refresh tokens.
     * @throws BadCredentialsException if authentication fails (e.g., invalid credentials).
     * @see JwtAuthResponse for more details.
     * @see LoginRequest for more details.
     */
    @Override
    @Transactional(readOnly = true)
    @RateLimit(limit = 10, period = 60)
    public JwtAuthResponse login(@NotNull LoginRequest loginRequest) {
        logger.info("Validating login request for email: {}", loginRequest.email());
        userDetailsValidations.validate(loginRequest);
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password())
            );
            logger.info("Successfully authenticated user: {}", loginRequest.email());

            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            String accessToken = jwtService.generateJwtToken(userDetails);
            Map<String, Object> refreshTokenClaims = Map.of("token_type", "refresh_token");
            String refreshToken = jwtService.generateRefreshToken(refreshTokenClaims, userDetails);

            return new JwtAuthResponse(accessToken, refreshToken);
        } catch (AuthenticationException e) {
            logger.error("Authentication failed for email: {}, Error: {}", loginRequest.email(), e.getMessage());
            throw new BadCredentialsException("Invalid email or password", e);
        }
    }

    /**
     * Refreshes the access token using the provided refresh token.
     * Validates the refresh token, verifies its authenticity and type, and generates new tokens if valid.
     *
     * @param refreshTokenRequest The request containing the refresh token.
     * @return A JwtAuthResponse containing the new access and refresh tokens.
     * @throws IllegalArgumentException if the refresh token is invalidly formatted.
     * @throws UsernameNotFoundException if the user is not found.
     * @throws InvalidTokenException if the refresh token is invalid or not a refresh token.
     */
    @Override
    @RateLimit
    public JwtAuthResponse refreshToken(@NotNull RefreshTokenRequest refreshTokenRequest) {
        String refreshToken = refreshTokenRequest.refreshToken();
        logger.info("Processing refresh token request");
        userDetailsValidations.validate(refreshTokenRequest);

        String username= null;
        try {
            username = jwtService.getUsernameFromToken(refreshTokenRequest.refreshToken());
            UserDetails userDetails = securityUserService.getUserDetailsService().loadUserByUsername(username);

            String tokenType = jwtService.getTokenType(refreshToken);
            if (!"refresh_token".equals(tokenType)) {
                logger.error("Token is not a refresh token for user: {}", username);
                throw new InvalidTokenException("Provided token is not a refresh token");
            }

            if (!jwtService.validateToken(refreshToken, userDetails)) {
                logger.error("Refresh token is invalid for user: {}", username);
                throw new InvalidTokenException("Invalid refresh token");
            }

            String accessToken = jwtService.generateJwtToken(userDetails);
            Map<String, Object> refreshClaims = Map.of("token_type", "refresh_token");
            String newRefreshToken = jwtService.generateRefreshToken(refreshClaims, userDetails);

            logger.info("Successfully refresh token for user: {}", username);
            return new JwtAuthResponse(accessToken, newRefreshToken);
        } catch (ExpiredJwtException e) {
            logger.error("Refresh token has expired for user: {}", username != null ? username : "unknown");
            throw new InvalidTokenException("Refresh token has expired", e);
        } catch (JwtException e) {
            logger.error("Failed to process refresh token for user: {}. Error: {}", username != null ? username : "unknown", e.getMessage());
            throw new InvalidTokenException("Invalid refresh token", e);
        }
    }

    /**
     * Initiates a password reset process for the user with the provided email.
     * Validates the email, generates a reset token, stores it, and sends an email to the user with the reset link.
     * @param email - The email of the user requesting a password reset.
     * @return - A PasswordResetDto containing the reset token and the email of the user.
     * @throws UserNotFoundException if the user with the provided email is not found.
     * @throws IllegalArgumentException if the email is invalid.
     */
    @Override
    @jakarta.transaction.Transactional
    @RateLimit(limit = 5, period = 3600)
    public PasswordResetDto forgotPassword(String email) {
        logger.info("Forgot password request for email: {}", email);

        userDetailsValidations.validate(email);

        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.error("User not found with email: {}", email);
                    return new UserNotFoundException("User not found with email: " + email);
                });

        Map<String, Object> claims = Map.of("type", "reset", "email", email);
        String resetToken = jwtService.generateRefreshToken(claims, new UserDetailsImpl(user));
        LocalDateTime expiry = LocalDateTime.now().plusMinutes(15);

        user.setResetToken(resetToken);
        user.setResetTokenExpiration(expiry);
        userRepository.save(user);

        // TODO: Implement this method to send the password reset email.
        // emailService.sendPasswordResetEmail(email, resetToken);

        logger.info("Password reset token generated an email sent for user: {}", email);
        return new PasswordResetDto(user.getId(), user.getEmail());
    }

    /**
     * Validates a password reset token and prepares for password reset.
     * Invalidates the token after successful validation.
     *
     * @param token The reset token to validate.
     * @return PasswordResetDto with minimal user info (e.g., id, email).
     */
    @Override
    @jakarta.transaction.Transactional
    @RateLimit
    public PasswordResetDto validateResetToken(String token) {
        logger.info("Initiating reset token validation");
        User user = validateAndGetUserByToken(token);

        user.setResetToken(null);
        user.setResetTokenExpiration(null);
        userRepository.save(user);

        logger.info("Reset token validated for user: {}", user.getEmail());
        return new PasswordResetDto(user.getId(), user.getEmail());
    }

    /**
     * Resets a user's password using a valid reset token.
     * Ensures the request comes from the authenticated user associated with the token.
     * Updates the password and invalidates the token.
     *
     * @param token The reset token previously sent to the user.
     * @param newPassword The new password to set for the user.
     * @throws IllegalArgumentException if the token or newPassword is null or blank.
     * @throws InvalidTokenException if the token is not found or doesn't match the authenticated user.
     * @throws TokenExpiredException if the token has expired.
     * @throws AuthenticationException if no authenticated user is present.
     */
    @Override
    @jakarta.transaction.Transactional
    @RateLimit
    public void resetPassword(String token, String newPassword) {
        logger.info("Reset password request initiated");

        if (newPassword == null || newPassword.isBlank()) {
            logger.error("New password is null or blank");
            throw new IllegalArgumentException("New password cannot be null or blank");
        }

        User user = validateAndGetUserByToken(token);

        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null);
        user.setResetTokenExpiration(null);
        userRepository.save(user);

        logger.info("Password reset successfully for user: {}", user.getEmail());
    }

    /**
     * Validates a reset token and returns the associated user.
     * Throws exceptions if the token is invalid or expired.
     *
     * @param token The reset token to validate.
     * @return The User entity associated with the token.
     * @throws IllegalArgumentException if the token is null or blank.
     * @throws InvalidTokenException if the token is not found.
     * @throws TokenExpiredException if the token has expired.
     */
    private @NotNull User validateAndGetUserByToken(String token) {
        if (token == null || token.isBlank()) {
            logger.error("Reset token is null or blank");
            throw new IllegalArgumentException("Reset token cannot be null or blank");
        }

        User user = userRepository.findByResetToken(token)
                .orElseThrow(() -> {
                    logger.error("Reset token not found: {}", token.substring(0, Math.min(token.length(), 8)) + "..."); // Log only the first 8 characters of the token
                    return new InvalidTokenException("Invalid reset token");
                });

        LocalDateTime expiry = user.getResetTokenExpiration();
        if (expiry == null || expiry.isBefore(LocalDateTime.now())) {
            logger.error("Reset token has expired for user: {}", user.getEmail());
            throw new TokenExpiredException("Reset token has expired");
        }
        return user;
    }
}
