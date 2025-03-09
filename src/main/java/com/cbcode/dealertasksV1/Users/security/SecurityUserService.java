package com.cbcode.dealertasksV1.Users.security;

import org.springframework.security.core.userdetails.UserDetailsService;

public interface SecurityUserService {
    UserDetailsService getUserDetailsService();
}
