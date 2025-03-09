package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.ExceptionsConfig.*;
import com.cbcode.dealertasksV1.Users.model.DTOs.UserDto;
import com.cbcode.dealertasksV1.Users.model.Role;
import com.cbcode.dealertasksV1.Users.model.User;
import com.cbcode.dealertasksV1.Users.repository.RoleRepository;
import com.cbcode.dealertasksV1.Users.repository.UserRepository;
import com.cbcode.dealertasksV1.Users.security.AdminService;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.SignUpRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.UserDetailsValidations;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.UserUpdateRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Response.UserDeletionResponse;
import com.cbcode.dealertasksV1.Users.security.JwtService;
import com.cbcode.dealertasksV1.Users.service.EmailService;
import jakarta.transaction.Transactional;
import org.jetbrains.annotations.NotNull;
import org.modelmapper.MappingException;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Objects;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import static com.cbcode.dealertasksV1.Users.model.Enums.EnumRole.ROLE_ADMIN;

@Service
public class AdminServiceImpl implements AdminService {

    private static final Logger logger = LoggerFactory.getLogger(AdminServiceImpl.class);
    private static final String USER_NOT_FOUND = "User not found";
    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final int MIN_PASSWORD_LENGTH = 8;
    private static final Pattern PASSWORD_PATTERN = Pattern.compile("^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,}$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile("^(.+)@(.+)$");
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RoleRepository roleRepository;
    private final ModelMapper modelMapper;
    private final EmailService emailService;
    private final UserDetailsValidations userDetailsValidations;

    public AdminServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, JwtService jwtService, AuthenticationManager authenticationManager,
                            RoleRepository roleRepository, ModelMapper modelMapper, EmailService emailService, UserDetailsValidations userDetailsValidations) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.authenticationManager = authenticationManager;
        this.roleRepository = roleRepository;
        this.modelMapper = modelMapper;
        this.emailService = emailService;
        this.userDetailsValidations = userDetailsValidations;
    }

    /**
     * @param signUpRequest - SignUpRequest object containing user details to be created in the database
     *                      (email, password, first name, last name, roles)
     * @throws UserCreationException      - if an error occurs while creating the user in the database
     * @throws AccessDeniedException      - if the user is not authorized to create a new user
     * @throws UserAlreadyExistsException - if a user with the same email already exists in the database
     * @throws IllegalArgumentException   - if the email is empty or null
     * @throws PasswordTooShortException  - if the password is too short
     * @throws RoleNotFoundException      - if a role is not found in the database
     * @see SignUpRequest for more details.
     */
    @Override
    @Transactional
    public void createUser(@NotNull SignUpRequest signUpRequest) {
        checkAdminAuthorization();
        checkEmailAvailability(signUpRequest.email());
        userDetailsValidations.validate(signUpRequest);

        Set<Role> roles = mapRoles(signUpRequest.roles());

        User user = new User();
        user.setFirstName(signUpRequest.firstName());
        user.setLastName(signUpRequest.lastName());
        user.setEmail(signUpRequest.email());
        user.setPassword(passwordEncoder.encode(signUpRequest.password()));
        user.setRoles(roles);
        user.setCreatedAt(LocalDateTime.now());

        try {
            User savedUser = userRepository.save(user);
            logger.info("User with email {} created!", signUpRequest.email());
            // TODO add a message to the welcome response email sent to the user.
            // On production, send welcome email asynchronously to avoid blocking the main thread while sending email.
            // sendWelcomeEmailAsync(savedUser);
        } catch (DataIntegrityViolationException e) {
            logger.error("Database constraint violation while creating user with email: {}. Error: {}", signUpRequest.email(), e.getMessage());
            throw new UserCreationException("Failed to create user: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Error while creating user with email: {}. Error: {}", signUpRequest.email(), e.getMessage());
            throw new UserCreationException("Failed to create user: " + e.getMessage());
        }

    }

    /**
     * Retrieves a user by their ID, restricted to admin users.
     * @param id the positive Long ID of the user to fetch
     * @return UserDto containing the user's details
     * @throws IllegalArgumentException if id is null or non-positive
     * @throws OperationNotPermittedException if the caller lacks admin privileges
     * @throws UserNotFoundException if no user exists with the given id
     * @throws UserRetrievalException if a database error occurs
     */
    @Override
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public UserDto getUserById(Long id) {
        logger.info("Attempting to fetch user with ID: {}", id);
        validateId(id, "Fetch");

        Authentication auth = getAuthentication();
        verifyAdminAccess(auth);

        try {
            User user = findUserById(id);
            logger.info("Successfully retrieved user with ID: {}", id);

            return convertToDto(user);
        } catch (DataAccessException e) {
            logger.error("Database constraint violation while fetching user with ID: {}", id, e);
            throw new UserRetrievalException("Failed to fetch user due to database error!" + e.getMessage());
        }
    }

    /**
     * Retrieves a paginated list of all users, restricted to admin users.
     * @param pageable pagination parameters (page number, size, and optional sorting)
     * @return a Page of UserDto objects containing user details (excluding sensitive data)
     * @throws IllegalArgumentException if pagination parameters are invalid
     * @throws OperationNotPermittedException if the caller lacks admin privileges
     * @throws UserRetrievalException if a database error occurs
     */
    @Override
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public Page<UserDto> getAllUsers(Pageable pageable) {
        logger.info("Attempting to fetch all users");
        validatePageable(pageable);

        Authentication auth = getAuthentication();
        verifyAdminAccess(auth);

        try {
            Page<User> usersPage = userRepository.findAll(pageable);
            logger.debug("Retrieved {} users on page {} of {}, size {}",
                    usersPage.getNumberOfElements(),
                    usersPage.getNumber(),
                    usersPage.getTotalPages(),
                    usersPage.getSize());

            return usersPage.map(this::convertToDto);
        } catch (DataAccessException e) {
            logger.error("Database constraint violation while fetching all users", e);
            throw new UserRetrievalException("Failed to fetch users due to database error!" + e.getMessage());
        }
    }

    /**
     * @param id
     * @param userUpdateRequest
     */
    @Override
    @Transactional(rollbackOn = Exception.class)
    public void updateUser(Long id, UserUpdateRequest userUpdateRequest) {
        validateInput(id, userUpdateRequest);
        logger.info("Attempting to update user with ID: {}", id);

        Authentication auth = getAuthentication();
        verifyAdminAccess(auth);

        try {
            User user = findUserById(id);
            logger.debug("Found user: {} for update", user.getEmail());

            validateUpdateRestrictions(user, userUpdateRequest);
            updateUserFields(user, userUpdateRequest);
            userRepository.save(user);
            logger.debug("User with ID: {} updated successfully", id);
        } catch (DataAccessException e) {
            logger.error("Database constraint violation while updating user with ID: {}", id, e);
            throw new UserUpdateException("Failed to update user due to database error!" + e.getMessage());
        }
    }

    /**
     * @param id
     */
    @Override
    @Transactional(rollbackOn = Exception.class)
    public UserDeletionResponse deleteUser(Long id) {
        validateId(id, "Delete");
        logger.info("Attempting to delete user with ID: {}", id);

        Authentication auth = getAuthentication();
        verifyAdminAccess(auth);

        try {
            User user = findUserById(id);
            validateUserDeletion(user, auth);

            userRepository.delete(user);
            logger.info("User {} with ID: {} deleted successfully",user.getEmail(), id);

            return new UserDeletionResponse(user.getId(), user.getEmail(), "User deleted successfully", LocalDateTime.now());
        } catch (DataAccessException e) {
            logger.error("Database constraint violation while deleting user with ID: {}", id, e);
            throw new UserDeletionException("Failed to delete user due to database error!" + e.getMessage());
        }
    }

    /**
     * @param id
     * @param roleNames
     * @return
     */
    @Override
    @Transactional(rollbackOn = Exception.class)
    public UserDto updateUserRole(Long id, Set<Role> roleNames) {
       validateRoleInput(id, roleNames);
       logger.info("Attempting to update user role with ID: {}", id);

         Authentication auth = getAuthentication();
            verifyAdminAccess(auth);

            try {
                User user = findUserById(id);
                logger.debug("Found user: {} for role update", user.getEmail());

                Set<Role> roles = validateAndFetchRoles(roleNames);
                updateUserRoles(user, roles);

                User updatedUser = userRepository.save(user);
                logger.info("User roles updated successfully: {}", updatedUser.getEmail());

                return convertToDto(updatedUser);
            } catch (DataAccessException e) {
                logger.error("Database constraint violation while updating user role with ID: {}", id, e);
                throw new UserUpdateException("Failed to update user role due to database error!" + e.getMessage());
            }
    }

    // Custom method to check if the user is authorized to create a new user (only Admins can create new users)
    private void checkAdminAuthorization() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || authentication.getAuthorities().stream().noneMatch(a -> a.getAuthority().equals("ROLE_ADMIN"))) {
            logger.error("User is not authorized to create a new user");
            throw new AccessDeniedException("Only Admins can create new users");
        }
    }

    // Custom method to check if a user with the same email already exists in the database
    private void checkEmailAvailability(String email) {
        if (userRepository.existsByEmail(email)) {
            logger.error("User with email {} already exists!", email);
            throw new UserAlreadyExistsException("User with email " + email + " already exists!");
        }
    }

    private Set<Role> mapRoles(Set<Role> requestedRoles) {
        try {
            return requestedRoles.stream()
                    .map(role -> roleRepository.findByName(role.getName())
                            .orElseThrow(() -> new RoleNotFoundException("Role not found: " + role.getName().name())))
                    .collect(Collectors.toSet());
        } catch (Exception e) {
            logger.error("Error while mapping roles: {}", e.getMessage());
            throw e;
        }
    }

    @Async
    public void sendWelcomeEmailAsync(User user) {
        try {
            emailService.sendEmail(
                    user.getEmail(),
                    "Welcome to DealerTasks",
                    "Welcome to DealerTasks, " + user.getFirstName() + "!\n\n" +
                            "We are excited to have you on board. If you have any questions or need help, please feel free to reach out to us.\n\n" +
                            "Best,\n" +
                            "DealerTasks Team"
            );
            logger.debug("Welcome email sent to {}", user.getEmail());
        } catch (Exception e) {
            logger.error("Error while sending welcome email to {}: {}", user.getEmail(), e.getMessage());
        }
    }

    // Helper Methods
    private void validateId(Long id, String operation) {
        if (id == null || id <= 0) {
            logger.error("Invalid ID for {} operation: {}", operation, id);
            throw new IllegalArgumentException("User ID must be a positive number");
        }
    }

    private void validateInput(Long id, UserUpdateRequest userUpdateRequest) {
        validateId(id, "update");
        if (userUpdateRequest == null) {
            logger.error("User DTO cannot be null for update ID: {}", id);
            throw new IllegalArgumentException("User details are required");
        }
    }

    private void validateRoleInput(Long id, Set<Role> roleNames) {
        validateId(id, "role update");
        if (roleNames == null || roleNames.isEmpty()) {
            logger.error("Role names cannot be null or empty for ID: {}", id);
            throw new IllegalArgumentException("At least one role must be provided");
        }
    }

    private void validatePageable(Pageable pageable) {
        if (pageable == null) {
            logger.error("Pageable is null");
            throw new IllegalArgumentException("Pagination parameters cannot be null");
        }
        if (pageable.getPageSize() <= 0) {
            logger.error("Invalid page size: {}", pageable.getPageSize());
            throw new IllegalArgumentException("Page size must be a positive number");
        }
        if (pageable.getPageSize() > 100) {
            logger.error("Page size too large: {}", pageable.getPageSize());
            throw new IllegalArgumentException("Page size must not exceed 100");
        }
        if (pageable.getPageNumber() < 0) {
            logger.error("Invalid page number: {}", pageable.getPageNumber());
            throw new IllegalArgumentException("Page number must be a positive number");
        }
    }

    private User findUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.warn("User not found with ID: {}", id);
                    return new UserNotFoundException(USER_NOT_FOUND + ": " + id);
                });
    }

    private User findUserByEmail(String email) {
        validateEmail(email);
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("User not found with email: {}", email);
                    return new UserNotFoundException(USER_NOT_FOUND + ": " + email);
                });
    }

    private void validateEmail(String email) {
        if (email == null || email.trim().isEmpty()) {
            logger.error("Invalid email: {}", email);
            throw new IllegalArgumentException("Email cannot be null or empty");
        }
    }

    private UserDto convertToDto(User user) {
        try {
            return modelMapper.map(user, UserDto.class);
        } catch (MappingException e) {
            logger.error("Mapping error for user ID: {}", user.getId(), e);
            throw new UserMappingException("Failed to map user to DTO", e);
        }
    }

    private void verifyAdminAccess(Authentication auth) {
        if (!hasRole(auth, ROLE_ADMIN)) {
            logger.warn("Non-admin {} attempted privileged operation", auth.getName());
            throw new OperationNotPermittedException("Admin privileges required");
        }
    }

    private void validateUserDeletion(User user, Authentication auth) {
        if (isAdmin(user)) {
            logger.warn("Blocked attempt to delete admin user: {}", user.getEmail());
            throw new OperationNotPermittedException("Deletion of admin users is not permitted: " + user.getEmail());
        }
    }

    private @NotNull Boolean isAdmin(@NotNull User user) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        String currentPrincipalName = authentication.getName();
        return user.getEmail().equals(currentPrincipalName) && authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> grantedAuthority.getAuthority().equals("ROLE_ADMIN"));
    }

    private boolean hasRole(Authentication auth, String role) {
        return auth != null && auth.getAuthorities().stream()
                .anyMatch(a -> a.getAuthority().equals(role));
    }

    private boolean hasRole(@NotNull User user, String role) {
        return user.getRoles().stream()
                .anyMatch(r -> r.getName().name().equals(role));
    }

    private void validateUpdateRestrictions(@NotNull User user, @NotNull UserUpdateRequest userUpdateRequest) {
        if (!userUpdateRequest.email().equals(user.getEmail())) {
            logger.warn("Attempt to change email from {} to {}", user.getEmail(), userUpdateRequest.email());
            throw new OperationNotPermittedException("Email updates not allowed");
        }
        if (!Objects.deepEquals(userUpdateRequest.roles(), user.getRoles())) {
            logger.warn("Attempt to modify roles via user update for {}", user.getEmail());
            throw new OperationNotPermittedException("Use updateUserRole for role changes");
        }
    }

    private void updateUserFields(@NotNull User user, @NotNull UserUpdateRequest userUpdateRequest) {
        user.setFirstName(userUpdateRequest.firstName());
        user.setLastName(userUpdateRequest.lastName());
        if (shouldUpdatePassword(userUpdateRequest)) {
            validateAndUpdatePassword(user, userUpdateRequest);
        }
        user.setUpdatedAt(LocalDateTime.now());
    }

    private boolean shouldUpdatePassword(@NotNull UserUpdateRequest userUpdateRequest) {
        return userUpdateRequest.password() != null && !userUpdateRequest.password().trim().isEmpty();
    }

    private void validateAndUpdatePassword(User user, @NotNull UserUpdateRequest userUpdateRequest) {
        String password = userUpdateRequest.password();
        if (password.length() < MIN_PASSWORD_LENGTH) {
            logger.warn("Password too short for user: {}", user.getEmail());
            throw new IllegalArgumentException("Password must be at least " + MIN_PASSWORD_LENGTH + " characters");
        }
        user.setPassword(passwordEncoder.encode(password));
    }

    private Set<Role> validateAndFetchRoles(@NotNull Set<Role> roles) {
        return roles.stream()
                .map(role -> {
                    if (role.getId() == null) {
                        return roleRepository.findByName(role.getName())
                                .orElseThrow(() -> {
                                    logger.warn("Role not found: {}", role.getName());
                                    return new RoleNotFoundException("Role not found: " + role.getName());
                                });
                    }
                    return roleRepository.findById(role.getId())
                            .orElseThrow(() -> {
                                logger.warn("Role not found with ID: {}", role.getId());
                                return new RoleNotFoundException("Role not found with ID: " + role.getId());
                            });
                })
                .collect(Collectors.toSet());
    }

    private void updateUserRoles(@NotNull User user, Set<Role> roles) {
        user.getRoles().clear();
        user.getRoles().addAll(roles);
    }

    private void validateDisableOperation(@NotNull User user, @NotNull Authentication auth) {
        User currentUser = findUserByEmail(auth.getName());
        if (currentUser.getId().equals(user.getId())) {
            logger.warn("Admin {} attempted to disable themselves", auth.getName());
            throw new OperationNotPermittedException("Cannot disable own account");
        }
        if (hasRole(user, String.valueOf(ROLE_ADMIN))) {
            logger.warn("Attempt to disable admin user: {}", user.getEmail());
            throw new OperationNotPermittedException("Cannot disable admin users");
        }
    }

    private Authentication getAuthentication() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null) {
            logger.error("No authentication context available");
            throw new OperationNotPermittedException("Authentication required");
        }
        return auth;
    }
}
