package com.nhvinh.ecommerce.controller;

import com.nhvinh.ecommerce.dto.AuthenticationRequest;
import com.nhvinh.ecommerce.dto.IntrospectRequest;
import com.nhvinh.ecommerce.dto.LogoutRequest;
import com.nhvinh.ecommerce.dto.RefreshRequest;
import com.nhvinh.ecommerce.dto.APIResponse;
import com.nhvinh.ecommerce.dto.AuthenticationResponse;
import com.nhvinh.ecommerce.dto.IntrospectResponse;
import com.nhvinh.ecommerce.service.AuthenticationService;
import com.nimbusds.jose.JOSEException;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.web.bind.annotation.*;

import java.text.ParseException;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class AuthenticationController {
    AuthenticationService authenticationService;
    @PostMapping("/login")
    APIResponse<AuthenticationResponse> authenticate(@RequestBody AuthenticationRequest request) {
        var result =  authenticationService.authenticate(request);
        return APIResponse.<AuthenticationResponse>builder()
                .code(1000)
                .result(result)
                .build();

    }

    @PostMapping("/introspect")
    APIResponse<IntrospectResponse> introspect(@RequestBody IntrospectRequest request) throws ParseException, JOSEException {
        var result =  authenticationService.introspect(request);
        return APIResponse.<IntrospectResponse>builder()
                .code(1000)
                .result(result)
                .build();
    }

    @PostMapping("/logout")
    APIResponse<Void> logout(@RequestBody LogoutRequest request) throws ParseException, JOSEException {
        authenticationService.logout(request);
        return APIResponse.<Void>builder()
                .build();
    }

    @PostMapping("refresh")
    APIResponse<AuthenticationResponse> authenticate(@RequestBody RefreshRequest request) throws ParseException, JOSEException {
        var result =  authenticationService.refreshToken(request);
        return APIResponse.<AuthenticationResponse>builder()
                .result(result)
                .build();

    }

    @GetMapping("/clean") //Clean expired token in table
    APIResponse<Void> cleanInvalidatedTokenTable() {
        authenticationService.cleanInvalidatedTokenTable();
        return APIResponse.<Void>builder()
                .build();
    }

}
