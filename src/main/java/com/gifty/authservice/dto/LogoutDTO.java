package com.gifty.authservice.dto;

import lombok.Data;

@Data
public class LogoutDTO {
    private String username;
    private String deviceId;
}