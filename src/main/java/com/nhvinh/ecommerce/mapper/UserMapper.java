package com.nhvinh.ecommerce.mapper;


import com.nhvinh.ecommerce.dto.UserCreationRequest;
import com.nhvinh.ecommerce.dto.UserResponse;
import com.nhvinh.ecommerce.entity.User;
import org.mapstruct.Mapper;
import org.mapstruct.Mapping;
import org.mapstruct.MappingTarget;

@Mapper(componentModel = "spring")
public interface UserMapper {
    //@Mapping(target = "createdAt", ignore = true)
    User toUser(UserCreationRequest request);
    UserResponse toUserResponse(User user);
}