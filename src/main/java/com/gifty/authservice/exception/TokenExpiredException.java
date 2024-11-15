package com.gifty.authservice.exception;
//Kullanım yeri: Refresh token doğrulaması sırasında JWT token süresi dolmuş olduğunda kullanılır.
public class TokenExpiredException extends RuntimeException {
    public TokenExpiredException(String message) {
        super(message);
    }
}
