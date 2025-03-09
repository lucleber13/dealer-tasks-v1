package com.cbcode.dealertasksV1.Users.security;

import com.cbcode.dealertasksV1.Users.model.DTOs.UserDto;
import com.cbcode.dealertasksV1.Users.model.Role;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.SignUpRequest;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.UserUpdateRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Set;

public interface AdminService {
    void createUser(SignUpRequest signUpRequest);
    UserDto getUserById(Long id);
    Page<UserDto> getAllUsers(Pageable pageable);
    void updateUser(Long id, UserUpdateRequest userUpdateRequest);
    void deleteUser(Long id);
    // Update the Role of a User by ID and Role ID
    UserDto updateUserRole(Long id, Set<Role> roleNames);
}
