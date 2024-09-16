package com.nhvinh.ecommerce.service;

import com.nhvinh.ecommerce.dto.RoleRequest;
import com.nhvinh.ecommerce.dto.RoleResponse;
import com.nhvinh.ecommerce.entity.Role;
import com.nhvinh.ecommerce.mapper.RoleMapper;
import com.nhvinh.ecommerce.repository.PermissionRepository;
import com.nhvinh.ecommerce.repository.RoleRepository;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.List;

@Getter
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class RoleService {
    RoleRepository roleRepository;
    PermissionRepository permissionRepository;
    RoleMapper roleMapper;

    public RoleResponse createRole(RoleRequest request) {
        Role role = roleMapper.toRole(request);
        var permissions = permissionRepository.findAllById(request.getPermissions());
        role.setPermissions(new HashSet<>(permissions));
        role = roleRepository.save(role);
        return roleMapper.toRoleResponse(role);
    }
    public List<RoleResponse> getAllRoles() {
        List<Role> roles = roleRepository.findAll();
        return roles.stream().map(roleMapper::toRoleResponse).toList();
    }
    public RoleResponse getRoleById(String id) {
        Role role = roleRepository.findById(id).orElse(null);
        return roleMapper.toRoleResponse(role);
    }
    public void deleteRoleById(String id) {
        roleRepository.deleteById(id);
    }
}
