package com.nhvinh.ecommerce.mapper;

import com.nhvinh.ecommerce.dto.PermissionRequest;
import com.nhvinh.ecommerce.dto.PermissionResponse;
import com.nhvinh.ecommerce.entity.Permission;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface PermissionMapper {
    Permission toPermission(PermissionRequest request);
    PermissionResponse toPermissionResponse(Permission permission);

}
