package com.nhvinh.ecommerce.service;

import com.nhvinh.ecommerce.constant.PredefinedRole;
import com.nhvinh.ecommerce.dto.UserCreationRequest;
import com.nhvinh.ecommerce.dto.UserResponse;
import com.nhvinh.ecommerce.entity.Role;
import com.nhvinh.ecommerce.entity.User;
import com.nhvinh.ecommerce.exception.CustomException;
import com.nhvinh.ecommerce.exception.ErrorCode;
import com.nhvinh.ecommerce.mapper.UserMapper;
import com.nhvinh.ecommerce.repository.RoleRepository;
import com.nhvinh.ecommerce.repository.UserRepository;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.extern.slf4j.Slf4j;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashSet;
import java.util.List;

@Service
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
@Slf4j
public class UserService {

    UserRepository userRepository;
    PasswordEncoder passwordEncoder;
    UserMapper userMapper;
    private final RoleRepository roleRepository;

    //@PreAuthorize("hasRole('ADMIN')") //Authorize by  Role
    //@PreAuthorize("hasAuthority('UPDATE_DATA')") //Authorize by Permission
    public List<UserResponse> getAllUser() {
        log.info("- ###### - getAllUser");
        List<User> users = userRepository.findAll();
        List<UserResponse> userResponses = new ArrayList<>();
        for (User user : users) {
            userResponses.add(userMapper.toUserResponse(user));
        }
        return userResponses;
    }

    public UserResponse createUser(UserCreationRequest request) {


        log.info("- ###### - createUser");
        System.out.println("request" + request);
        User user = userMapper.toUser(request);
        System.out.println(user);
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        user.setCreatedAt(LocalDate.now());
        user.setUpdatedAt(LocalDate.now());


        HashSet<Role> roles = new HashSet<>();
        roleRepository.findById(PredefinedRole.USER_ROLE).ifPresent(roles::add);

        user.setRoles(roles);

        try {
            user = userRepository.save(user);
        }
        catch (DataIntegrityViolationException e) {
            throw new CustomException(ErrorCode.USER_EXISTED);
        }
        return  userMapper.toUserResponse(user);
    }

    //@PostAuthorize("returnObject.username == authentication.name")
    public UserResponse getUserById(String userId) {
        log.info("- ###### - getUserById");
        return userMapper.toUserResponse(userRepository.findById(userId).orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_EXISTED)));
    }

    public UserResponse getMyInfo() {
        log.info("- ###### - getMyInfo: ");

        var context = SecurityContextHolder.getContext();
        String name = context.getAuthentication().getName();
        return userMapper.toUserResponse(userRepository.findByUsername(name).orElseThrow(() -> new CustomException(ErrorCode.USER_NOT_EXISTED)));
    }

//    public UserResponse updateUserById(String userId, UserUpdateRequest request) {
//        User userToUpdate = userRepository.findById(userId).orElseThrow(() -> new RuntimeException("User not found"));
//
//        userMapper.updateUser(userToUpdate, request);
//        userToUpdate.setPassword(passwordEncoder.encode(request.getPassword()));
//        var roles = roleRepository.findAllById(request.getRoles());
//        userToUpdate.setRoles(new HashSet<>(roles));
//        return userMapper.toUserResponse(userRepository.save(userToUpdate));
//    }

    public void deleteUserById(String userId) {
        userRepository.deleteById(userId);
    }
}
