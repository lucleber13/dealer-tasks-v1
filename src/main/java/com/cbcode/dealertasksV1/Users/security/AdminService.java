package com.cbcode.dealertasksV1.Users.security;

import com.cbcode.dealertasksV1.Users.model.DTOs.UserDto;
import com.cbcode.dealertasksV1.Users.model.Role;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.SignUpRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;

import java.util.Set;

public interface AdminService {

    void createUser(SignUpRequest signUpRequest);

    UserDto getUserDetailsById(Long id);

    Page<UserDto> getAllUsers(Pageable pageable);

    void updateUser(Long id, UserDto userDto);

    void deleteUser(Long id);

    // Update the Role of a User by ID and Role ID
    void updateUserRole(Long id, Set<Role> roleNames);

    void updateUserEmail(Long userId, String email);
}
