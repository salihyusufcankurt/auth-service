package com.gifty.authservice.exception;

/**
 * Refresh token ile ilgili istisnalar için kullanılır.
 */
public class RefreshTokenInvalidException extends RuntimeException {
    public RefreshTokenInvalidException(String message) {
        super(message);
    }
}