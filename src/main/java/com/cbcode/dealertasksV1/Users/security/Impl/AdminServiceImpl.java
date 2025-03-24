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
import com.cbcode.dealertasksV1.Users.service.EmailService;
import jakarta.persistence.EntityNotFoundException;
import jakarta.transaction.Transactional;
import org.jetbrains.annotations.Contract;
import org.jetbrains.annotations.NotNull;
import org.modelmapper.MappingException;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;


@Service
public class AdminServiceImpl implements AdminService {

    private static final Logger logger = LoggerFactory.getLogger(AdminServiceImpl.class);
    private static final String USER_NOT_FOUND = "User not found";
    private static final String ROLE_ADMIN = "ROLE_ADMIN";
    private static final String ACTION_FETCH = "fetch";
    @Value("${app.pagination.max-page-size}")
    private int maxPageSize;
    @Value("${app.security.password.min-password-length}")
    private int minPasswordLength;
    @Value("${app.security.password.pattern}")
    private String passwordPattern;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final ModelMapper modelMapper;
    private final EmailService emailService;
    private final UserDetailsValidations userDetailsValidations;

    public AdminServiceImpl(UserRepository userRepository, PasswordEncoder passwordEncoder, RoleRepository roleRepository,
                            ModelMapper modelMapper, EmailService emailService, UserDetailsValidations userDetailsValidations) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.roleRepository = roleRepository;
        this.modelMapper = modelMapper;
        this.emailService = emailService;
        this.userDetailsValidations = userDetailsValidations;
    }

    /**
     * Creates a new user in the system based on the provided sign-up request.
     * Validates user details, checks email availability, and ensures proper authorization
     * before creating and saving the user.
     * Handles post-creation operations if successful,
     * or manages errors if any issues arise during the process.
     *
     * @param signUpRequest the sign-up request containing user details for account creation
     *                      (e.g., email, password, personal information)
     */
    @Override
    @Transactional
    public void createUser(@NotNull SignUpRequest signUpRequest) {
        try {
            ValidationUtil.validateEmail(signUpRequest.email());
            verifyAdminAccess();
            checkEmailAvailability(signUpRequest.email());
            userDetailsValidations.validate(signUpRequest);

            User user = createAndSaveUser(signUpRequest, mapRoles(signUpRequest.roles()));
            logger.info("User with email {} created: ", signUpRequest.email());
            // handlePostUserCreation(user, signUpRequest.email());
        } catch (Exception e) {
            handleUserCreationErrors(e, signUpRequest.email());
        }
    }

    private void handlePostUserCreation(User savedUser) {
        // sendWelcomeEmailAsync(savedUser);
    }

    /**
     * Validates if the currently authenticated user has admin privileges.
     * This method retrieves the authentication object from the security context
     * and checks if the user possesses the required admin role.
     * If there is no authentication context or the user does not have the admin role,
     * an AccessDeniedException is thrown.
     * Throws:
     * - AccessDeniedException if there is no authentication available or
     * the user does not have the required admin role.
     */
    private void verifyAdminAccess() {
        Authentication authentication = getAuthentication();

        // Check if the user has ROLE_ADMIN authority
        boolean isAdmin = authentication.getAuthorities().stream()
                .anyMatch(grantedAuthority -> ROLE_ADMIN.equals(grantedAuthority.getAuthority()));

        if (!isAdmin) {
            logger.warn("Non-admin attempted to create user: {}", authentication.getName());
            throw new AccessDeniedException("Only Admins can perform this operation");
        }

        logger.debug("Admin authorization successful for user: {}", authentication.getName());

    }

    /**
     * Retrieves the current authentication object from the security context.
     * This method ensures that an authentication object is present and throws
     * an exception if it cannot be found.
     *
     * @return the current {@link Authentication} object, never null
     * @throws OperationNotPermittedException if no authentication context is available
     */
    private @NotNull Authentication getAuthentication() {
        return Optional.ofNullable(SecurityContextHolder.getContext())
                .map(SecurityContext::getAuthentication)
                .filter(Authentication::isAuthenticated)
                .orElseThrow(() -> {
                    logger.error("No authentication context available");
                    return new AccessDeniedException("User is not authenticated");
                });
    }

    /**
     * Checks the availability of the given email address in the user repository.
     * If the email address already exists, an error is logged, and a
     * UserAlreadyExistsException is thrown.
     *
     * @param email the email address to check for availability
     */
    private void checkEmailAvailability(String email) {
        if (userRepository.existsByEmail(email)) {
            logger.error("User with email {} already exists!", email);
            throw new UserAlreadyExistsException("User with email " + email + " already exists!");
        }
    }

    /**
     * Creates and returns a new {@link User} object initialized
     * with data provided in the {@link SignUpRequest}.
     *
     * @param signUpRequest the sign-up request containing user details and roles
     * @return a {@link User} object created from the provided sign-up request
     */
    private @NotNull User createAndSaveUser(@NotNull SignUpRequest signUpRequest, Set<Role> roles) {
        User user = new User();
        user.setFirstName(signUpRequest.firstName());
        user.setLastName(signUpRequest.lastName());
        user.setEmail(signUpRequest.email());
        user.setPassword(passwordEncoder.encode(signUpRequest.password()));
        user.setRoles(roles);
        user.setCreatedAt(LocalDateTime.now());
        return userRepository.save(user);
    }

    /**
     * Maps a set of roles to another set of roles using the mapping logic defined in the mapRole method.
     *
     * @param rolesToMap the set of roles to be mapped; must not be null
     * @return a new set of roles after applying the mapping logic
     */
    private Set<Role> mapRoles(@NotNull Set<Role> rolesToMap) {
        return rolesToMap.stream()
                .map(this::mapRole)
                .collect(Collectors.toSet());
    }

    /**
     * Maps a given role to a corresponding role entity from the repository.
     *
     * @param role the role to map, must not be null
     * @return the matching role entity from the repository
     * @throws RoleNotFoundException if the role with the specified name is not found in the repository
     */
    private Role mapRole(@NotNull Role role) {
        return roleRepository.findByName(role.getName())
                .orElseThrow(() ->
                        new RoleNotFoundException("Role with name " + role.getName().name() + " not found!"));
    }

    /**
     * Handles errors encountered during the user creation process and logs appropriate messages.
     * Converts specific exceptions into a custom UserCreationException for consistent error handling.
     *
     * @param e     The exception that occurred during user creation.
     * @param email The email address of the user being created, used for logging purposes.
     * @throws UserCreationException Thrown when user creation fails due to any exception.
     */
    private void handleUserCreationErrors(Exception e, String email) {
        if (e instanceof DataIntegrityViolationException) {
            logger.error("Database constraint violation while creating user with email: {}. Error: {}", email, e.getMessage());
            throw new UserCreationException("Email already exists" + e.getMessage());
        }
        logger.error("Error while creating user with email: {}. Error: {}", email, e.getMessage());
        throw new UserCreationException("Failed to create user: " + e.getMessage());
    }

    /**
     * Fetches the user details for a given user ID.
     *
     * @param id The unique identifier of the user whose details are to be retrieved. Must not be null.
     * @return A UserDto object containing the details of the user.
     * @throws IllegalArgumentException if the provided ID is null or invalid.
     * @throws AccessDeniedException    if the caller does not have sufficient permissions.
     * @throws UserRetrievalException   if an error occurs during the retrieval of the user details.
     */
    @Override
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public UserDto getUserDetailsById(Long id) {
        logger.info("Attempting to fetch user with ID: {}", id);

        ValidationUtil.validateId(id, ACTION_FETCH);
        verifyAdminAccess();

        try {
            User user = findUserById(id);
            logger.info("Successfully retrieved user with ID: {}", id);
            return mapUserToDto(user);
        } catch (DataAccessException e) {
            logger.error("Failed to fetch user with ID: {} due to a database error {}", id, e.getMessage());
            throw new UserRetrievalException("Database error occurred while fetching user details.");
        }
    }

    /**
     * Finds a user by their unique identifier.
     *
     * @param id the unique identifier of the user to find
     * @return the user with the specified identifier
     * @throws UserNotFoundException if no user is found with the given identifier
     */
    private User findUserById(Long id) {
        return userRepository.findById(id)
                .orElseThrow(() -> {
                    logger.warn("User not found with ID: {}", id);
                    return new UserNotFoundException(USER_NOT_FOUND + ": " + id);
                });
    }

    /**
     * Maps a User object to a UserDto object.
     *
     * @param user the User object to be mapped; must not be null.
     * @return the mapped UserDto object.
     * @throws IllegalArgumentException if the user parameter is null.
     * @throws UserMappingException     if an error occurs during the mapping process.
     */
    private UserDto mapUserToDto(final User user) {
        if (user == null) {
            throw new IllegalArgumentException("User object cannot be null");
        }
        try {
            return modelMapper.map(user, UserDto.class);
        } catch (MappingException e) {
            logger.error("Mapping error for user ID: {}", user.getId(), e);
            throw new UserMappingException("Failed to map user to DTO", e);
        }
    }

    /**
     * Retrieves a paginated list of all users.
     *
     * @param pageable the pagination information including page number, size, and sorting options
     * @return a paginated Page of UserDto objects representing the users
     * @throws UserRetrievalException if a database access error occurs during retrieval
     */
    @Override
    @org.springframework.transaction.annotation.Transactional(readOnly = true)
    public Page<UserDto> getAllUsers(Pageable pageable) {
        logger.info("Attempting to fetch all users");
        validatePageable(pageable);
        verifyAdminAccess();

        try {
            Page<User> userPage = userRepository.findAll(pageable);
            logger.debug("Retrieved {} users on page {} of {}, size {}",
                    userPage.getNumberOfElements(),
                    userPage.getNumber(),
                    userPage.getTotalPages(),
                    userPage.getSize());

            return userPage.map(this::mapUserToDto);
        } catch (DataAccessException e) {
            logger.error("Database constraint violation while fetching all users", e);
            throw new UserRetrievalException("Failed to fetch users due to database error!" + e.getMessage());
        }
    }

    /**
     * Validates the given Pageable object to ensure its parameters are within acceptable ranges.
     *
     * @param pageable the Pageable object containing pagination parameters to be validated.
     *                 Must not be null.
     * @throws IllegalArgumentException if the pageable object is null, if the page size is
     *                                  not a positive number, if the page size exceeds the
     *                                  maximum allowed size, or if the page number is negative.
     */
    private void validatePageable(Pageable pageable) {
        if (pageable == null) {
            logger.error("Pageable is null");
            throw new IllegalArgumentException("Pagination parameters cannot be null");
        }
        if (pageable.getPageSize() <= 0) {
            logger.error("Invalid page size: {}", pageable.getPageSize());
            throw new IllegalArgumentException("Page size must be a positive number");
        }
        if (pageable.getPageSize() > maxPageSize) {
            logger.error("Page size exceeds maximum allowed: {}", pageable.getPageSize());
            throw new IllegalArgumentException("Page size exceeds maximum allowed");
        }
        if (pageable.getPageNumber() < 0) {
            logger.error("Invalid page number: {}", pageable.getPageNumber());
            throw new IllegalArgumentException("Page number must be a positive number");
        }
    }

    /**
     * Updates the details of an existing user.
     * This method validates the input, checks for admin access,
     * and performs the necessary updates to the user information.
     *
     * @param id      the ID of the user to be updated
     * @param userDto the data transfer object containing updated user information
     */
    @Override
    @Transactional(rollbackOn = Exception.class)
    public void updateUser(Long id, UserDto userDto) {
        logger.info("Attempting to update user with ID: {}", id);

        ValidationUtil.validateId(id, "update");
        if (userDto == null) {
            logger.error("User DTO cannot be null for update ID: {}", id);
            throw new IllegalArgumentException("User details are required");
        }

        verifyAdminAccess();
        try {
            User user = findUserById(id);
            validateUpdateRestrictions(user, userDto);
            updateUserFields(user, userDto);
            userRepository.save(user);
            logger.debug("User with ID: {} updated successfully", id);
        } catch (DataAccessException e) {
            logger.error("Database constraint violation while updating user with ID: {}", id, e);
            throw new UserUpdateException("Failed to update user due to database error!" + e.getMessage());
        }
    }

    /**
     * Validates if the update operation on a user's attributes respects the update restrictions.
     * Throws an exception if restricted operations are detected, such as email updates.
     *
     * @param user    the current User object from the database that needs validation
     * @param userDto the incoming UserDto object containing updated user information
     * @throws OperationNotPermittedException if an attempt to update restricted fields is detected
     */
    private void validateUpdateRestrictions(@NotNull User user, @NotNull UserDto userDto) {
        if (!userDto.getEmail().equals(user.getEmail())) {
            logger.warn("Attempt to change email from {} to {}", user.getEmail(), userDto.getEmail());
            throw new OperationNotPermittedException("Email updates not allowed through this method");
        }
//        if (!Objects.deepEquals(userDto.roles(), user.getRoles())) {
//            logger.warn("Attempt to modify roles via user update for {}", user.getEmail());
//            throw new OperationNotPermittedException("Use updateUserRole for role changes");
//        }
    }

    /**
     * Updates the fields of a given User object with the values provided in the UserDto object.
     * This includes updating basic user information and conditionally updating the user's password
     * if specified.
     * The user's update timestamp is also set to the current time.
     *
     * @param user    the User object to be updated
     * @param userDto the UserDto object containing the new values for the User fields
     */
    private void updateUserFields(@NotNull User user, @NotNull UserDto userDto) {
        user.setFirstName(userDto.getFirstName());
        user.setLastName(userDto.getLastName());

        if (userDto.getPassword() != null && !userDto.getPassword().trim().isEmpty()) {
            validateAndUpdatePassword(user, userDto);
        }
        user.setUpdatedAt(LocalDateTime.now());
    }

    /**
     * Validates the provided password and updates the user's password if validation succeeds.
     *
     * @param user    the user object whose password is to be updated; must not be null.
     * @param userDto the data transfer object containing the new password and other user information; must not be null.
     */
    private void validateAndUpdatePassword(@NotNull User user, @NotNull UserDto userDto) {
        String password = userDto.getPassword();
        validatePassword(password, userDto.getEmail());
        user.setPassword(passwordEncoder.encode(password));
    }

    /**
     * Validates the given password based on predefined rules such as minimum length
     * and pattern matching for complexity requirements.
     *
     * @param password the password string to validate; must not be null
     * @param email    the email associated with the user, used for logging purposes
     * @throws PasswordTooShortException if the password length is less than the minimum required length
     * @throws IllegalArgumentException  if the password does not meet complexity requirements,
     *                                   such as containing at least one uppercase letter,
     *                                   one lowercase letter, one digit, and one special character
     */
    private void validatePassword(@NotNull String password, String email) {
        if (password.length() < minPasswordLength) {
            logger.warn("Password too short for user: {}", email);
            throw new PasswordTooShortException("Password must be at least " + minPasswordLength + " characters");
        }
        // TODO: Uncomment the following code to enforce password complexity requirements
//        if (!Pattern.compile(passwordPattern).matcher(password).matches()) {
//            logger.warn("Invalid password format for user: {}", email);
//            throw new IllegalArgumentException("Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character");
//        }
    }

    /**
     * Deletes a user from the system based on the provided user ID. This method validates the
     * ID, checks admin access, ensures that the user can be deleted based on business rules,
     * and removes the user record from the database.
     * In case of a database constraint violation
     * or a database access issue, a {@code UserDeletionException} is thrown.
     *
     * @param id the ID of the user to be deleted; must not be null and must correspond to an existing user
     * @throws IllegalArgumentException if the provided ID is invalid or null
     * @throws AccessDeniedException    if the authenticated user lacks admin privileges
     * @throws UserNotFoundException    if no user is found with the provided ID
     * @throws UserDeletionException    if the deletion fails due to database constraints or access errors
     */
    @Override
    @Transactional(rollbackOn = Exception.class)
    public void deleteUser(Long id) {
        ValidationUtil.validateId(id, "Delete");
        logger.info("Attempting to delete user with ID: {}", id);

        verifyAdminAccess();
        try {
            User user = findUserById(id);
            ensureUserDeletionPermitted(user);
            userRepository.delete(user);
            logger.info("User {} with ID: {} deleted successfully", user.getEmail(), id);
        } catch (DataAccessException e) {
            logger.error("Database constraint violation while deleting user with ID: {}", id, e);
            throw new UserDeletionException("Failed to delete user due to database error!" + e.getMessage());
        }
    }

    /**
     * Ensures that the provided user is permitted to be deleted.
     *
     * @param user the user to check
     */
    private void ensureUserDeletionPermitted(@NotNull User user) {
        boolean isAdmin = user.getRoles().stream()
                .anyMatch(role -> "ROLE_ADMIN".equalsIgnoreCase(role.getName().name()));

        if (isAdmin) {
            logger.warn("Deletion of admin users is not permitted");
            throw new OperationNotPermittedException("Deletion of admin users is not permitted");
        }
    }

    /**
     * Updates the roles of a user identified by the given ID. Validates the input and
     * ensures that the caller has administrative access before performing the update.
     * Successfully updated roles will be persisted in the database.
     *
     * @param id        the unique identifier of the user whose roles are to be updated
     * @param roleNames the set of roles to be assigned to the user
     * @throws IllegalArgumentException if the provided ID or roles are invalid
     * @throws UserNotFoundException    if the user is not found for the given ID
     * @throws AccessDeniedException    if the caller does not have administrative access
     * @throws UserUpdateException      if the role update fails due to database constraints or other reasons
     */
    @Override
    @Transactional(rollbackOn = Exception.class)
    public void updateUserRole(Long id, Set<Role> roleNames) {
        logger.info("Attempting to update user role with ID: {}", id);

        ValidationUtil.validateId(id, "role update");
        if (roleNames == null || roleNames.isEmpty()) {
            logger.error("Role names cannot be null or empty for ID: {}", id);
            throw new IllegalArgumentException("At least one role must be provided");
        }

        verifyAdminAccess();

        try {
            User user = findUserById(id);
            logger.debug("Found user: {} for role update", user.getEmail());

            Set<Role> roles = validateAndFetchRoles(roleNames);
            user.setRoles(roles);
            user.setUpdatedAt(LocalDateTime.now());

            userRepository.save(user);
            logger.info("User roles updated successfully: {}", user.getEmail());
        } catch (DataAccessException e) {
            logger.error("Database constraint violation while updating user role with ID: {}", id, e);
            throw new UserUpdateException("Failed to update user role due to database error!" + e.getMessage());
        }
    }

    /**
     * Validates and fetches roles by processing the provided set of roles.
     * Each role is matched or retrieved
     * using its identifier or name.
     *
     * @param roles the set of roles to validate and fetch; must not be null
     * @return a set of roles after validation and retrieval
     */
    private Set<Role> validateAndFetchRoles(@NotNull Set<Role> roles) {
        return roles.stream()
                .map(this::fetchRoleByIdOrName)
                .collect(Collectors.toSet());
    }

    /**
     * Fetches a Role either by its ID or by its name.
     * If the ID is null, the method searches by the name.
     * If the Role cannot be found, it throws a RoleNotFoundException.
     *
     * @param role the Role object containing either an ID or a name that will be used to look up the Role
     * @return the Role object fetched from the repository
     * @throws RoleNotFoundException if no Role is found with the provided ID or name
     */
    private Role fetchRoleByIdOrName(@NotNull Role role) {
        if (role.getId() == null) {
            return roleRepository.findByName(role.getName())
                    .orElseThrow(() ->
                            new RoleNotFoundException("Role not found: " + role.getName()));
        }

        return roleRepository.findById(role.getId())
                .orElseThrow(() ->
                        new RoleNotFoundException("Role not found with ID: " + role.getId()));
    }

    /**
     * Updates the email address of a user specified by userId.
     * The method validates inputs,
     * checks administrative access, and ensures the new email is different from the current one
     * before updating the user's email in the system.
     *
     * @param userId The unique identifier of the user whose email is to be updated.
     * @param email  The new email address to be assigned to the user.
     * @throws IllegalArgumentException If the provided userId or email is invalid.
     * @throws AccessDeniedException    If the caller does not have the necessary permissions.
     * @throws EntityNotFoundException  If no user with the specified userId exists in the system.
     */
    @Override
    @Transactional(rollbackOn = Exception.class)
    public void updateUserEmail(Long userId, String email) {
        logger.info("Attempting to update email for user with ID: {}", userId);

        ValidationUtil.validateId(userId, "email update");
        ValidationUtil.validateEmail(email);

        verifyAdminAccess();

        try {
            User user = findUserById(userId);
            if (user.getEmail().equals(email)) {
                logger.warn("No change in email for user with ID: {}", userId);
                return;
            }
            checkEmailAvailability(email);
            user.setEmail(email);
            user.setUpdatedAt(LocalDateTime.now());

            userRepository.save(user);
            logger.info("User email updated successfully for ID: {}", userId);
        } catch (DataAccessException e) {
            logger.error("Database error while updating email for user with ID: {}", userId, e);
            throw new UserUpdateException("Failed to update email due to database error: " + e.getMessage());
        }
    }

    /**
     * Sends a welcome email to a newly registered user asynchronously.
     *
     * @param newUser the user to whom the welcome email will be sent. Must contain valid email details.
     */
    @Async
    public void sendWelcomeEmailAsync(User newUser) {
        try {
            String emailBody = generateWelcomeEmailBody(newUser);
            emailService.sendEmail(newUser.getEmail(), emailBody, "Welcome to DealerTasks");
            logger.debug("Successfully sent welcome email to {}", newUser.getEmail());
        } catch (Exception e) {
            logger.error("Failed to send welcome email to {}: {}", newUser.getEmail(), e.getMessage());
        }
    }

    /**
     * Generates the body content for a welcome email personalized for the given user.
     *
     * @param user the user for whom the welcome email body is being generated; must not be null
     * @return the generated email body as a non-null string
     */
    private @NotNull String generateWelcomeEmailBody(@NotNull User user) {
        return "Welcome to DealerTasks, " + user.getFirstName() + "!\n\n" +
                "We are excited to have you on board. If you have any questions or need help, please feel free to reach out to us.\n\n" +
                "Best,\n" +
                "DealerTasks Team";
    }

    /**
     * Finds a user based on the provided email address.
     *
     * @param email the email address of the user to be found, must not be null or empty
     * @return the User object if found
     * @throws UserNotFoundException if no user is found with the specified email
     */
    private User findUserByEmail(String email) {
        ValidationUtil.validateEmail(email);
        return userRepository.findByEmail(email)
                .orElseThrow(() -> {
                    logger.warn("User not found with email: {}", email);
                    return new UserNotFoundException(USER_NOT_FOUND + ": " + email);
                });
    }
}
