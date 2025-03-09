package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.Users.model.DTOs.UserDto;
import com.cbcode.dealertasksV1.Users.repository.RoleRepository;
import com.cbcode.dealertasksV1.Users.repository.UserRepository;
import com.cbcode.dealertasksV1.Users.security.AuthService;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.LoginRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.RefreshTokenRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.UserDetailsValidations;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.JwtAuthResponse;
import com.cbcode.dealertasksV1.Users.security.JwtService;
import com.cbcode.dealertasksV1.Users.security.SecurityUserService;
import com.cbcode.dealertasksV1.Users.service.EmailService;
import org.jetbrains.annotations.NotNull;
import org.modelmapper.ModelMapper;
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

import java.util.Map;

@Service
public class AuthServiceImpl implements AuthService {

    private static final Logger logger = LoggerFactory.getLogger(AuthServiceImpl.class);

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RoleRepository roleRepository;
    private final ModelMapper modelMapper;
    private final EmailService emailService;
    private final SecurityUserService securityUserService;
    private final UserDetailsValidations userDetailsValidations;

    public AuthServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager,
                           RoleRepository roleRepository, ModelMapper modelMapper, EmailService emailService, SecurityUserService securityUserService,
                           UserDetailsValidations userDetailsValidations) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.roleRepository = roleRepository;
        this.modelMapper = modelMapper;
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
            throw new BadCredentialsException("Invalid email or password");
        }
    }

    /**
     * @param refreshTokenRequest
     * @return
     */
    @Override
    public JwtAuthResponse refreshToken(RefreshTokenRequest refreshTokenRequest) {
        return null;
    }

    /**
     *
     */
    @Override
    public void logout() {

    }

    /**
     * @param email
     * @return
     */
    @Override
    public UserDto forgotPassword(String email) {
        return null;
    }

    /**
     * @param token
     * @return
     */
    @Override
    public UserDto validateResetToken(String token) {
        return null;
    }

    /**
     * @param token
     * @param newPassword
     */
    @Override
    public void resetPassword(String token, String newPassword) {

    }


}
