package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.Users.repository.UserRepository;
import com.cbcode.dealertasksV1.Users.security.SecurityUserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class SecurityUserServiceImpl implements SecurityUserService {

    private static final Logger logger = LoggerFactory.getLogger(SecurityUserServiceImpl.class);
    private final UserRepository userRepository;

    public SecurityUserServiceImpl(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * @return UserDetailsService object that loads user by email from the database and returns AuthUser object if found
     *
     */
    @Override
    public UserDetailsService getUserDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                logger.info("Loading user by email: {}", email);
                return userRepository.findByEmail(email)
                        .map(UserDetailsImpl::new)
                        .orElseThrow(() -> {
                            logger.error("User not found with email: {}", email);
                            return new UsernameNotFoundException("User not found with email: " + email);
                        });
            }
        };
    }
}
