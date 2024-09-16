package com.nhvinh.ecommerce.service;

import com.nhvinh.ecommerce.dto.PermissionRequest;
import com.nhvinh.ecommerce.dto.PermissionResponse;
import com.nhvinh.ecommerce.entity.Permission;
import com.nhvinh.ecommerce.mapper.PermissionMapper;
import com.nhvinh.ecommerce.repository.PermissionRepository;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Getter
@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class PermissionService {
    PermissionRepository permissionRepository;
    PermissionMapper permissionMapper;

    public PermissionResponse createPermission(PermissionRequest request) {
        Permission permission = permissionMapper.toPermission(request);
        permission = permissionRepository.save(permission);
        return permissionMapper.toPermissionResponse(permission);
    }
    public List<PermissionResponse> getAllPermissions() {
        List<Permission> permissions = permissionRepository.findAll();
        return permissions.stream().map(permissionMapper::toPermissionResponse).toList();
    }
    public PermissionResponse getPermissionById(String id) {
        Permission permission = permissionRepository.findById(id).orElse(null);
        return permissionMapper.toPermissionResponse(permission);
    }
    public void deletePermissionById(String id) {
        permissionRepository.deleteById(id);
    }
}
