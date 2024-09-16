package com.nhvinh.ecommerce.dto;


import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.FieldDefaults;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)

public class UserCreationRequest {

    @Size(min = 4, message = "INVALID_USERNAME")
    String username;
    @Size(min = 4, message = "INVALID_PASSWORD")
    String password;
    String firstName;
    String lastName;
    String email;
    String phone;
    String address;

}
