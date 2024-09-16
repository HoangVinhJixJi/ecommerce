package com.nhvinh.ecommerce.exception;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter

public class CustomException extends RuntimeException {

    public CustomException(ErrorCode errorCode) {
        super(errorCode.getMessage());
        this.errorCode = errorCode;
    }

    private ErrorCode errorCode;

}

