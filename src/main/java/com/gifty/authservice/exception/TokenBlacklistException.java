package com.gifty.authservice.exception;

/**
 * Blacklist'te bulunan token istisnaları için kullanılır.
 */
public class TokenBlacklistException extends RuntimeException {
    public TokenBlacklistException(String message) {
        super(message);
    }
}