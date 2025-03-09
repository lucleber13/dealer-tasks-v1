package com.cbcode.dealertasksV1.Users.controller;

import com.cbcode.dealertasksV1.Users.security.AdminService;
import com.cbcode.dealertasksV1.Users.security.DTOs.Request.SignUpRequest;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/admin")
@PreAuthorize("hasAuthority('ROLE_ADMIN')")
@CrossOrigin(origins = "*")
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    @PostMapping("/signup")
    //@PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public ResponseEntity<String> signUp(@RequestBody @Valid SignUpRequest signUpRequest) {
        adminService.createUser(signUpRequest);
        // TODO: add a message to the welcome response email sent to the user.
        return ResponseEntity.ok("User with email " + signUpRequest.email() + " created!");
    }
}
