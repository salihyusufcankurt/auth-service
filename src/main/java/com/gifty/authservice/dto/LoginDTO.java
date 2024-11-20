package com.gifty.authservice.dto;

import lombok.Data;

@Data
public class LoginDTO {
    private String username;
    private String password;
    private String deviceName; // Cihaz adı (ör. tarayıcı bilgisi)
    private String location; // Kullanıcının konum bilgisi

}
