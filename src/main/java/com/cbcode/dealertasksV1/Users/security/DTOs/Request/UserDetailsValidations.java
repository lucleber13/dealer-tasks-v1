package com.cbcode.dealertasksV1.Users.security.DTOs.Request;

import com.cbcode.dealertasksV1.ExceptionsConfig.PasswordTooShortException;
import com.cbcode.dealertasksV1.ExceptionsConfig.RoleNotFoundException;
import com.cbcode.dealertasksV1.ExceptionsConfig.UserAlreadyExistsException;
import com.cbcode.dealertasksV1.ExceptionsConfig.UserNotFoundException;
import com.cbcode.dealertasksV1.Users.model.Role;
import com.cbcode.dealertasksV1.Users.repository.UserRepository;
import org.jetbrains.annotations.NotNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.regex.Pattern;

@Service
public class UserDetailsValidations {

    private static final Logger logger = LoggerFactory.getLogger(UserDetailsValidations.class);
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^[A-Za-z0-9+_.-]+@(.+)$");
    private static final Integer MIN_PASSWORD_LENGTH = 8;
    private final UserRepository userRepository;

    public UserDetailsValidations(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public void validate(@NotNull LoginRequest loginRequest) {
        validateEmail(loginRequest.email());
        validatePassword(loginRequest.password());
    }

    public void validate(@NotNull SignUpRequest signUpRequest) {
        validateFirstName(signUpRequest.firstName());
        validateLastName(signUpRequest.lastName());
        validateEmail(signUpRequest.email());
        validatePassword(signUpRequest.password());
        validateRole(signUpRequest.roles());
    }

    public void validate(@NotNull UserUpdateRequest userUpdateRequest) {
        if (userUpdateRequest.firstName() != null) validateFirstName(userUpdateRequest.firstName());
        if (userUpdateRequest.lastName() != null) validateLastName(userUpdateRequest.lastName());
        if (userUpdateRequest.email() != null) validateEmail(userUpdateRequest.email());
        if (userUpdateRequest.password() != null) validatePassword(userUpdateRequest.password());
    }

    public void validate(String email) {
        validateEmail(email);
    }

    public void validate(@NotNull RefreshTokenRequest refreshTokenRequest) {
        validateRefreshToken(refreshTokenRequest.refreshToken());
    }

    private void validateFirstName(String firstName) {
        if (firstName == null || firstName.isBlank()) {
            logger.error("First name cannot be null or empty");
            throw new IllegalArgumentException("First name cannot be null or empty");
        }
    }

    private void validateLastName(String lastName) {
        if (lastName == null || lastName.isBlank()) {
            logger.error("Last name cannot be null or empty");
            throw new IllegalArgumentException("Last name cannot be null or empty");
        }
    }

    private void validateEmail(String email) {
        if (email == null || email.isBlank()) {
            logger.error("Email cannot be null or empty");
            throw new UserNotFoundException("Email cannot be null or empty");
        }
        if (!EMAIL_PATTERN.matcher(email).matches()) {
            logger.error("Invalid email format: {}", email);
            throw new IllegalArgumentException("Invalid email format");
        }
    }

    private void validatePassword(String password) {
        if (password == null || password.isBlank()) {
            logger.error("Password cannot be null or empty");
            throw new IllegalArgumentException("Password cannot be null or empty");
        }
        if (password.length() < MIN_PASSWORD_LENGTH) {
            logger.error("Password must be at least {} characters long", MIN_PASSWORD_LENGTH);
            throw new PasswordTooShortException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters long");
        }
        //        TODO: Remove the comment below after implementing the password pattern validation
//        if (!PASSWORD_PATTERN.matcher(password).matches()) {
//            logger.error("Password does not meet the requirements: {}", password);
//            throw new PasswordTooShortException("Password does not meet the requirements. Password must contain at least one digit, one lowercase letter, one uppercase letter, one special character and no whitespace.");
//        }
    }

    private void validateRole(Set<Role> roles) {
        if (roles == null) {
            logger.error("Role cannot be null");
            throw new RoleNotFoundException("Role cannot be null");
        }
    }

    private void validateRefreshToken(String refreshToken) {
        if (refreshToken == null || refreshToken.isEmpty()) {
            logger.error("Refresh token cannot be null or empty");
            throw new IllegalArgumentException("Refresh token is null or empty");
        }
    }
}
