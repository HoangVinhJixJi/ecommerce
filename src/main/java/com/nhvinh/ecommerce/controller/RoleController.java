package com.nhvinh.ecommerce.controller;

import com.nhvinh.ecommerce.dto.APIResponse;
import com.nhvinh.ecommerce.dto.RoleRequest;
import com.nhvinh.ecommerce.dto.RoleResponse;
import com.nhvinh.ecommerce.service.RoleService;
import jakarta.validation.Valid;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/role")
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j

public class RoleController {

    RoleService roleService;
    @PostMapping("/create")
    APIResponse<RoleResponse> createRole(@RequestBody @Valid RoleRequest request) {
        APIResponse<RoleResponse> response = new APIResponse<>();
        response.setResult(roleService.createRole(request));
        response.setMessage("Role created successfully");
        return response;
    }
    @GetMapping("/all")
    APIResponse<List<RoleResponse>> getAllRoles(){
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        authentication.getAuthorities().forEach(
                grantedAuthority -> log.info("role: {}",grantedAuthority.getAuthority())
        );
       return  APIResponse.<List<RoleResponse>>builder()
               .result(roleService.getAllRoles())
               .build();

    }
    @GetMapping("/{roleId}")
    APIResponse<RoleResponse> getRole(@PathVariable("roleId") String roleId){
        return APIResponse.<RoleResponse>builder()
                .result(roleService.getRoleById(roleId))
                .build();
    }

    @DeleteMapping("delete/{roleId}")
    String deleteRole(@PathVariable String roleId){
        roleService.deleteRoleById(roleId);
        return "Role deleted";
    }

}
