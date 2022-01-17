package com.spring.devMedical.controllers;

//import javax.validation.Valid;

import com.spring.devMedical.models.ERole;
import com.spring.devMedical.models.Role;
import com.spring.devMedical.payload.response.MessageResponse;
import com.spring.devMedical.repository.RoleRepository;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/role")
public class RoleController {

    @Autowired
    private RoleRepository roleRepository;

    @PostMapping("/add")
    public ResponseEntity<?> addRole(/* @Valid @RequestBody(required = true) String role_name */) {

        Role role_doctor = new Role(ERole.ROLE_DOCTOR);
        roleRepository.save(role_doctor);

        Role role_admin = new Role(ERole.ROLE_ADMIN);
        roleRepository.save(role_admin);

        Role role_user = new Role(ERole.ROLE_USER);
        roleRepository.save(role_user);

        // return ResponseEntity.ok().body("Roles [DOCTOR , ADMIN , USER] was Added
        // successfully ...");
        return ResponseEntity.ok(new MessageResponse("Roles [DOCTOR , ADMIN , USER] was Added successfully ..."));
    }

}