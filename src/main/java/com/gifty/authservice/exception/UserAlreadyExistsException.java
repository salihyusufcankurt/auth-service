package com.gifty.authservice.exception;

//Kullanım yeri: AuthService register fonksiyonunda, kullanıcı adı veya e-posta zaten kullanılıyorsa kullanılır.
public class UserAlreadyExistsException extends RuntimeException {
    public UserAlreadyExistsException(String message) {
        super(message);
    }
}