package com.cbcode.dealertasksV1.Users.security.DTOs.Request;

import com.cbcode.dealertasksV1.Users.model.Role;

import java.util.Set;

public record SignUpRequest(String firstName, String lastName, String email, String password, Set<Role> roles) {

}
