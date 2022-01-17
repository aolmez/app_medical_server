package com.spring.devMedical.exception;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

@ResponseStatus(HttpStatus.BAD_REQUEST)
public class PasswordNotConfirmedException extends RuntimeException {
    private static final long serialVersionUID = 1L;

    public PasswordNotConfirmedException(String message) {
        super(String.format("Password Is Not Comfirmed : { %s }", message));
    }
}