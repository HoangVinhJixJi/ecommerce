package com.nhvinh.ecommerce.controller;

import com.nhvinh.ecommerce.dto.APIResponse;
import com.nhvinh.ecommerce.dto.PermissionRequest;
import com.nhvinh.ecommerce.dto.PermissionResponse;
import com.nhvinh.ecommerce.service.PermissionService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/permission")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j

public class PermissionController {

    PermissionService permissionService;
    @PostMapping("/create")
    APIResponse<PermissionResponse> createPermission(@RequestBody @Valid PermissionRequest request) {
        APIResponse<PermissionResponse> response = new APIResponse<>();
        response.setResult(permissionService.createPermission(request));
        response.setMessage("Permission created successfully");
        return response;
    }
    @GetMapping("/all")
    APIResponse<List<PermissionResponse>> getAllPermissions(){
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        authentication.getAuthorities().forEach(
                grantedAuthority -> log.info("role: {}",grantedAuthority.getAuthority())
        );
       return  APIResponse.<List<PermissionResponse>>builder()
               .result(permissionService.getAllPermissions())
               .build();

    }
    @GetMapping("/{permissionId}")
    APIResponse<PermissionResponse> getPermission(@PathVariable("permissionId") String permissionId){
        return APIResponse.<PermissionResponse>builder()
                .result(permissionService.getPermissionById(permissionId))
                .build();
    }

    @DeleteMapping("delete/{permissionId}")
    String deletePermission(@PathVariable String permissionId){
        permissionService.deletePermissionById(permissionId);
        return "Permission deleted";
    }

}
