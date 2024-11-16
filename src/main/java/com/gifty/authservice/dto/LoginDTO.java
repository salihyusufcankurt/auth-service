package com.gifty.authservice.dto;

import lombok.Data;

@Data
public class LoginDTO {
    private String username;
    private String password;
    private String deviceId;
}
