package com.cbcode.dealertasksV1.Users.security.Impl;

import com.cbcode.dealertasksV1.Users.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.stream.Collectors;

public class UserDetailsImpl implements UserDetails {
    private final String email;
    private final String password;
    private final Collection<? extends GrantedAuthority> authorities;

    public UserDetailsImpl(User user) {
        this.email = user.getEmail();
        this.password = user.getPassword();
        this.authorities = user.getRoles()
                .stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    /**
     * @return - true
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * @return - true
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * @return - true
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * @return - true
     */
    @Override
    public boolean isEnabled() {
        return true;
    }
}
