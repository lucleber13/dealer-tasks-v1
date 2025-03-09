package com.cbcode.dealertasksV1.Users.model.DTOs;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

import java.util.Objects;
import java.util.Set;

public class UserDto {
    private Long id;
    @Email(message = "Invalid email format")
    private String email;
    private String password;
    private Set<RoleDto> roles;
    @NotBlank(message = "First name is required")
    private String firstName;
    @NotBlank(message = "Last name is required")
    private String lastName;

    public UserDto() {
    }

    public UserDto(String email, String password, Set<RoleDto> roles, String firstName, String lastName) {
        this.email = email;
        this.password = password;
        this.roles = roles;
        this.firstName = firstName;
        this.lastName = lastName;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public Set<RoleDto> getRoles() {
        return roles;
    }

    public void setRoles(Set<RoleDto> roles) {
        this.roles = roles;
    }

    public String getFirstName() {
        return firstName;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public String getLastName() {
        return lastName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    @Override
    public boolean equals(Object o) {
        if (!(o instanceof UserDto userDto)) return false;
        return Objects.equals(id, userDto.id)
                && Objects.equals(email, userDto.email)
                && Objects.equals(password, userDto.password)
                && Objects.equals(roles, userDto.roles)
                && Objects.equals(firstName, userDto.firstName)
                && Objects.equals(lastName, userDto.lastName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id, email, password, roles, firstName, lastName);
    }
}
