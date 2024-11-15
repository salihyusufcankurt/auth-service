package com.gifty.authservice.exception;

//Kullanım yeri: Refresh token doğrulaması sırasında JWT token geçersiz olduğunda kullanılır.
public class InvalidTokenException extends RuntimeException {
    public InvalidTokenException(String message) {
        super(message);
    }
}
