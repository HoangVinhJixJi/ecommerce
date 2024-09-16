package com.nhvinh.ecommerce.mapper;

import com.nhvinh.ecommerce.dto.RoleRequest;
import com.nhvinh.ecommerce.dto.RoleResponse;
import com.nhvinh.ecommerce.entity.Role;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;

@Mapper(componentModel = "spring")
public interface RoleMapper {
    @Mapping(target = "permissions", ignore = true)
    Role toRole(RoleRequest request);
    RoleResponse toRoleResponse(Role permission);

}
