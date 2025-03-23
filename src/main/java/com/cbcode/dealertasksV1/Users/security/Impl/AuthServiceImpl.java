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
import io.jsonwebtoken.JwtException;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);
    private static final String REFRESH_TOKEN_TYPE = "refresh_token";
    private static final int PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES = 15;
    private static final String RESET_TOKEN_VALIDATED_LOG = "Reset token validated for user: {}";
    private static final int TOKEN_PREVIEW_LENGTH = 8;

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
     * Authenticates a user based on the provided login request and generates a JWT authentication response.
     * The method first validates the incoming login request, attempts user authentication,
     * and if successful, generates a token-based authentication response.
     * This method employs rate limiting and is read-only transactional.
     *
     * @param loginRequest the login request containing the user's email and password.
     * @return a {@code JwtAuthResponse} containing the authentication details and JWT token.
     * @throws BadCredentialsException if the authentication fails due to invalid email or password.
     */
    @Override
    @Transactional(readOnly = true)
    @RateLimit(limit = 10, period = 60)
    public JwtAuthResponse login(@NotNull LoginRequest loginRequest) {
        logger.info("Validating login request for email: {}", loginRequest.email());
        userDetailsValidations.validate(loginRequest);

        try {
            Authentication authentication = authenticateUser(loginRequest);
            UserDetails authenticatedUserDetails = (UserDetails) authentication.getPrincipal();
            return generateAuthResponse(authenticatedUserDetails);
        } catch (AuthenticationException e) {
            logAuthenticationError(loginRequest.email(), e);
            throw new BadCredentialsException("Invalid email or password", e);
        }
    }

    /**
     * Authenticates a user using the provided login request credentials.
     *
     * @param loginRequest the login request containing the user's email and password; must not be null.
     * @return an Authentication object representing the authenticated user and their authorities.
     */
    private Authentication authenticateUser(@NotNull LoginRequest loginRequest) {
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.email(), loginRequest.password())
        );
    }

    /**
     * Generates an authentication response containing access and refresh tokens for the given user details.
     *
     * @param userDetails the user details of the authenticated user; must not be null
     * @return a {@link JwtAuthResponse} object containing the generated access and refresh tokens
     */
    private @NotNull JwtAuthResponse generateAuthResponse(@NotNull UserDetails userDetails) {
        logger.info("Successfully authenticated user: {}", userDetails.getUsername());
        String accessToken = jwtService.generateJwtToken(userDetails);
        Map<String, Object> refreshTokenClaims = Map.of("token_type", REFRESH_TOKEN_TYPE);
        String refreshToken = jwtService.generateRefreshToken(refreshTokenClaims, userDetails);
        return new JwtAuthResponse(accessToken, refreshToken);
    }

    private void logAuthenticationError(@NotNull String email, @NotNull AuthenticationException e) {
        logger.error("Authentication failed for email: {}, Error: {}", email, e.getMessage());
    }

    /**
     * Handles the refresh token request and generates new authentication tokens.
     *
     * @param refreshTokenRequest The request containing the refresh token to be processed.
     * @return A {@link JwtAuthResponse} containing the newly generated tokens.
     */
    @Override
    @RateLimit
    public JwtAuthResponse refreshToken(@NotNull RefreshTokenRequest refreshTokenRequest) {
        String refreshToken = refreshTokenRequest.refreshToken();
        logger.info("Processing refresh token request");
        userDetailsValidations.validate(refreshTokenRequest);

        String userName = validateAndGetUsername(refreshToken);
        UserDetails userDetails = loadUserDetails(userName);

        validateTokenDetails(refreshToken, userDetails);

        return generateNewTokens(userDetails);
    }

    /**
     * Validates the provided refresh token and extracts the username from it.
     *
     * @param refreshToken the refresh token to validate and extract the username from
     * @return the extracted username if the token is valid
     * @throws InvalidTokenException if the refresh token is invalid or the username cannot be extracted
     */
    private String validateAndGetUsername(String refreshToken) {
        try {
            return jwtService.getUsernameFromToken(refreshToken);
        } catch (JwtException e) {
            logger.error("Failed to extract username from refresh token. Error: {}", e.getMessage());
            throw new InvalidTokenException("Invalid refresh token", e);
        }
    }

    /**
     * Loads the user details for a given username.
     *
     * @param username the username of the user whose details are to be fetched
     * @return the {@code UserDetails} object containing user information
     */
    private UserDetails loadUserDetails(String username) {
        return securityUserService.getUserDetailsService().loadUserByUsername(username);
    }

    /**
     * Validates the provided refresh token to ensure it is valid and matches the user details.
     *
     * @param refreshToken the refresh token to be validated; must not be null
     * @param userDetails  the user details associated with the token; must not be null
     * @throws InvalidTokenException if the token is not a refresh token or if it is invalid
     */
    private void validateTokenDetails(@NotNull String refreshToken, @NotNull UserDetails userDetails) {
        String tokenType = jwtService.getTokenType(refreshToken);

        if (!REFRESH_TOKEN_TYPE.equals(tokenType)) {
            logger.error("Token is not a refresh token for user: {}", userDetails.getUsername());
            throw new InvalidTokenException("Provided token is not a refresh token");
        }

        if (!jwtService.validateToken(refreshToken, userDetails)) {
            logger.error("Refresh token is invalid for user: {}", userDetails.getUsername());
            throw new InvalidTokenException("Invalid refresh token");
        }
    }

    /**
     * Generates new JWT access and refresh tokens for the given user details.
     *
     * @param userDetails The details of the user for whom the tokens are to be generated.
     *                    Must not be null.
     * @return A {@link JwtAuthResponse} containing the newly generated access token and refresh token.
     */
    @Contract("_ -> new")
    private @NotNull JwtAuthResponse generateNewTokens(@NotNull UserDetails userDetails) {
        String accessToken = jwtService.generateJwtToken(userDetails);
        Map<String, Object> refreshTokenClaims = Map.of("token_type", REFRESH_TOKEN_TYPE);
        String newRefreshToken = jwtService.generateRefreshToken(refreshTokenClaims, userDetails);
        logger.info("Generated new refresh token for user: {}", userDetails.getUsername());
        return new JwtAuthResponse(accessToken, newRefreshToken);
    }

    /**
     * Handles forgot password requests by validating the email, generating a password
     * reset token, and sending an email with the reset details to the user.
     *
     * @param email The email address of the user requesting password reset. Must be a valid and registered email address.
     * @return A {@code PasswordResetDto} containing the user's ID and email address for confirmation of the reset request.
     * @throws IllegalArgumentException if the provided email is invalid or null.
     * @throws UserNotFoundException    if no user is found with the provided email address.
     */
    @Override
    @jakarta.transaction.Transactional
    @RateLimit(limit = 5, period = 3600)
    public PasswordResetDto forgotPassword(String email) {
        logger.info("Forgot password request for email: {}", email);

        // Validate input email
        userDetailsValidations.validate(email);

        // Find user by email
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.error("User not found with email: {}", email);
                    return new UserNotFoundException("User not found with email: " + email);
                });
        // Generate and save password reset token
        generateResetToken(email, user);

        // Log completion and return response DTO
        logger.info("Password reset token generated an email sent for user: {}", email);
        return new PasswordResetDto(user.getId(), user.getEmail());
    }

    /**
     * Generates a password reset token for a user and updates the user's reset token
     * and its expiration time in the repository.
     *
     * @param email The email address of the user requesting the password reset.
     * @param user  The user object for which the reset token is being generated.
     */
    private void generateResetToken(String email, User user) {
        Map<String, Object> claims = Map.of("type", "reset", "email", email);
        String passwordResetToken = jwtService.generateRefreshToken(claims, new UserDetailsImpl(user));
        LocalDateTime resetExpiryToken = LocalDateTime.now().plusMinutes(PASSWORD_RESET_TOKEN_EXPIRATION_MINUTES);

        user.setResetToken(passwordResetToken);
        user.setResetTokenExpiration(resetExpiryToken);
        userRepository.save(user);

        // TODO: Implement this method to send the password reset email.
        // emailService.sendPasswordResetEmail(email, resetToken);
    }

    /**
     * Validates the provided reset token and invalidates it upon successful verification.
     *
     * @param token the reset token to be validated
     * @return a PasswordResetDto object containing information related to the user and reset process
     */
    @Override
    @jakarta.transaction.Transactional
    @RateLimit
    public PasswordResetDto validateAndInvalidateResetToken(String token) {
        logger.info("Initiating reset token validation");
        User user = fetchUserByResetToken(token);
        invalidateUserResetToken(user);
        logger.info(RESET_TOKEN_VALIDATED_LOG, user.getEmail());
        return createPasswordResetDto(user);
    }

    /**
     * Invalidates the reset token for the specified user by setting the reset token
     * and its expiration to null and then saving the updated user object.
     *
     * @param user the user for whom the reset token will be invalidated; must not be null
     */
    private void invalidateUserResetToken(@NotNull User user) {
        user.setResetToken(null);
        user.setResetTokenExpiration(null);
        userRepository.save(user);
    }

    /**
     * Creates a PasswordResetDto object using the provided User.
     *
     * @param user the User-object to be used for creating the PasswordResetDto.
     *             It must not be null.
     * @return a newly created PasswordResetDto containing the user's ID and email.
     */
    @Contract("_ -> new")
    private @NotNull PasswordResetDto createPasswordResetDto(@NotNull User user) {
        return new PasswordResetDto(user.getId(), user.getEmail());
    }

    /**
     * Resets the user's password using the provided token and new password.
     * This method validates the provided new password and updates the user's password
     * if the token is valid.
     *
     * @param token       The unique token used to authorize the password reset.
     * @param newPassword The new password to set for the user.
     */
    @Override
    @jakarta.transaction.Transactional
    @RateLimit
    public void resetPassword(String token, String newPassword) {
        logger.info("Reset password request initiated");

        validatePassword(newPassword);
        User user = fetchUserByResetToken(token);
        updateUserPassword(user, newPassword);
        logger.info("Password reset successfully completed for user: {}", user.getEmail());
    }

    /**
     * Validates the provided password string to ensure it is not null or blank.
     * Throws an IllegalArgumentException if the validation fails.
     *
     * @param newPassword the password-string to be validated
     */
    private void validatePassword(String newPassword) {
        final String INVALID_PASSWORD_MESSAGE = "New password cannot be null or blank";
        if (newPassword == null || newPassword.isBlank()) {
            logger.error("Password validation failed: {}", INVALID_PASSWORD_MESSAGE);
            throw new IllegalArgumentException(INVALID_PASSWORD_MESSAGE);
        }
    }

    /**
     * Updates the password for a given user and clears any reset tokens associated with the user.
     * The new password is encoded before being set.
     *
     * @param user        the user whose password is to be updated; must not be null
     * @param newPassword the new password to be set for the user; must not be null
     */
    private void updateUserPassword(@NotNull User user, @NotNull String newPassword) {
        user.setPassword(passwordEncoder.encode(newPassword));
        user.setResetToken(null);
        user.setResetTokenExpiration(null);
        userRepository.save(user);
        logger.info("User password updated successfully in the database. User: {}", user.getEmail());
    }


    /**
     * Fetches a user by their reset token. This method validates the given token format, retrieves
     * the corresponding user from the repository, and checks if the provided reset token has expired.
     *
     * @param token The reset token associated with a user. This parameter must not be null or empty
     *              and must conform to the expected token format.
     * @return The user linked to the provided reset token. Never null.
     * @throws InvalidTokenException If the reset token is invalid or not found.
     * @throws TokenExpiredException If the reset token has expired.
     */
    private @NotNull User fetchUserByResetToken(String token) {
        validateTokenFormat(token);

        String tokenPreview = token.substring(0, Math.min(token.length(), TOKEN_PREVIEW_LENGTH)) + "...";

        User user = userRepository.findByResetToken(token)
                .orElseThrow(() -> {
                    logger.error("Reset token not found: {}", tokenPreview); // Log only the first 8 characters of the token
                    return new InvalidTokenException("Invalid reset token");
                });

        LocalDateTime resetTokenExpiry = user.getResetTokenExpiration();
        if (resetTokenExpiry == null || resetTokenExpiry.isBefore(LocalDateTime.now())) {
            logger.error("Reset token has expired for user: {}", user.getEmail());
            throw new TokenExpiredException("Reset token has expired");
        }
        return user;
    }

    /**
     * Validates the format of the provided token to ensure it is neither null nor blank.
     *
     * @param token the reset token to be validated
     * @throws IllegalArgumentException if the token is null or blank
     */
    private void validateTokenFormat(String token) {
        if (token == null || token.isBlank()) {
            logger.error("Reset token is null or blank");
            throw new IllegalArgumentException("Reset token cannot be null or blank");
        }
    }
}
