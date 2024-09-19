package com.nhvinh.ecommerce.controller;

import com.nhvinh.ecommerce.dto.AuthenticationRequest;
import com.nhvinh.ecommerce.dto.IntrospectRequest;
import com.nhvinh.ecommerce.dto.LogoutRequest;
import com.nhvinh.ecommerce.dto.RefreshRequest;
import com.nhvinh.ecommerce.dto.ApiResponse;
import com.nhvinh.ecommerce.dto.AuthenticationResponse;
import com.nhvinh.ecommerce.dto.IntrospectResponse;
import com.nhvinh.ecommerce.service.AuthenticationService;
import com.nimbusds.jose.JOSEException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@Slf4j
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationController {
    AuthenticationService authenticationService;
    @PostMapping("/login")
    ApiResponse<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        log.info("function authenticate in AuthenticationController");
        var result =  authenticationService.authenticate(request);
        return ApiResponse.<AuthenticationResponse>builder()
                .code(1000)
                .result(result)
                .build();

    }

    @PostMapping("/introspect")
    ApiResponse<IntrospectResponse> introspect(@RequestBody IntrospectRequest request) throws ParseException, JOSEException {
        log.info("function introspect in AuthenticationController");
        var result =  authenticationService.introspect(request);
        return ApiResponse.<IntrospectResponse>builder()
                .code(1000)
                .result(result)
                .build();
    }

    @PostMapping("/logout")
    ApiResponse<Void> logout(@RequestBody LogoutRequest request) throws ParseException, JOSEException {
        log.info("function logout in AuthenticationController");
        authenticationService.logout(request);

        return ApiResponse.<Void>builder()
                .code(1000)
                .message("Logout successful!")
                .build();
    }

    @PostMapping("refresh")
    ApiResponse<AuthenticationResponse> authenticate(@RequestBody RefreshRequest request) throws ParseException, JOSEException {
        log.info("function refresh in AuthenticationController");
        var result =  authenticationService.refreshToken(request);
        return ApiResponse.<AuthenticationResponse>builder()
                .result(result)
                .build();

    }

    @GetMapping("/clean") //Clean expired token in table
    ApiResponse<Void> cleanInvalidatedTokenTable() {
        authenticationService.cleanInvalidatedTokenTable();
        return ApiResponse.<Void>builder()
                .build();
    }

}
