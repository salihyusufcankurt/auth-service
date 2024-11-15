package com.gifty.authservice.exception;

//Kullanım yeri: Register sırasında, şifre veya kullanıcı tipi geçersiz olduğunda kullanılır.
public class InvalidInputException extends RuntimeException {
    public InvalidInputException(String message) {
        super(message);
    }
}
