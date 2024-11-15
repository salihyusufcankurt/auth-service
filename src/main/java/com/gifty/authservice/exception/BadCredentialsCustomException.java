package com.gifty.authservice.exception;

//Kullanım yeri: AuthService login fonksiyonunda, kullanıcı adı veya şifre yanlış olduğunda kullanılır.
public class BadCredentialsCustomException extends RuntimeException {
    public BadCredentialsCustomException(String message) {
        super(message);
    }
}