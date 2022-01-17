package com.spring.devMedical.payload.request;

import javax.validation.constraints.NotNull;

public class LogOutRequest {

    // @NotBlank
    @NotNull
    private Long userId;

    public Long getUserId() {
        return userId;
    }

}