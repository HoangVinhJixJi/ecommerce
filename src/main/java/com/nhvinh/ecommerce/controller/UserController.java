package com.nhvinh.ecommerce.controller;


import com.nhvinh.ecommerce.dto.APIResponse;
import com.nhvinh.ecommerce.dto.UserCreationRequest;
import com.nhvinh.ecommerce.dto.UserResponse;
import com.nhvinh.ecommerce.entity.User;
import com.nhvinh.ecommerce.service.UserService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/user")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class UserController {

    UserService userService;
    @PostMapping("/create")
    APIResponse<UserResponse> createUser(@RequestBody @Valid UserCreationRequest request) {
        APIResponse<UserResponse> response = new APIResponse<>();
        response.setResult(userService.createUser(request));
        response.setMessage("User created successfully");
        return response;
    }
    @GetMapping("/")
    APIResponse<List<UserResponse>> getAllUsers(){
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        log.info("Username: {}", authentication.getName());
        authentication.getAuthorities().forEach(
                grantedAuthority -> log.info("role: {}",grantedAuthority.getAuthority())
        );
        return  APIResponse.<List<UserResponse>>builder()
                .result(userService.getAllUser())
                .build();

    }
    @GetMapping("/{userId}")
    APIResponse<UserResponse> getUser(@PathVariable("userId") String userId){
        return APIResponse.<UserResponse>builder()
                .result(userService.getUserById(userId))
                .build();
    }
    @GetMapping("/my-info")
    APIResponse<UserResponse> getUser(){
        return APIResponse.<UserResponse>builder()
                .result(userService.getMyInfo())
                .build();
    }

    @DeleteMapping("delete/{userId}")
    String deleteUser(@PathVariable String userId){
        userService.deleteUserById(userId);
        return "User deleted";
    }


}
