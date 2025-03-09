package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.ExceptionsConfig.PasswordTooShortException;
import com.cbcode.dealertasksV1.ExceptionsConfig.RoleNotFoundException;
import com.cbcode.dealertasksV1.ExceptionsConfig.UserAlreadyExistsException;
import com.cbcode.dealertasksV1.ExceptionsConfig.UserCreationException;
import com.cbcode.dealertasksV1.Users.model.DTOs.UserDto;
import com.cbcode.dealertasksV1.Users.model.Role;
import com.cbcode.dealertasksV1.Users.model.User;
import com.cbcode.dealertasksV1.Users.repository.RoleRepository;
import com.cbcode.dealertasksV1.Users.repository.UserRepository;
import com.cbcode.dealertasksV1.Users.security.AdminService;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.SignUpRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.UserDetailsValidations;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.UserUpdateRequest;
import com.cbcode.dealertasksV1.Users.security.JwtService;
import com.cbcode.dealertasksV1.Users.service.EmailService;
import jakarta.transaction.Transactional;
import org.jetbrains.annotations.NotNull;
import org.modelmapper.ModelMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
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
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

@Service
public class AdminServiceImpl implements AdminService {

    private static final Logger logger = LoggerFactory.getLogger(AdminServiceImpl.class);
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
     * @param id
     * @return
     */
    @Override
    public UserDto getUserById(Long id) {
        return null;
    }

    /**
     * @param pageable
     * @return
     */
    @Override
    public Page<UserDto> getAllUsers(Pageable pageable) {
        return null;
    }

    /**
     * @param id
     * @param userUpdateRequest
     */
    @Override
    public void updateUser(Long id, UserUpdateRequest userUpdateRequest) {

    }

    /**
     * @param id
     */
    @Override
    public void deleteUser(Long id) {

    }

    /**
     * @param id
     * @param roleNames
     * @return
     */
    @Override
    public UserDto updateUserRole(Long id, Set<Role> roleNames) {
        return null;
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
}
