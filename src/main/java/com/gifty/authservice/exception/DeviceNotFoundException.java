package com.gifty.authservice.exception;

/**
 * Cihaz bulunamadığında fırlatılan istisna.
 */
public class DeviceNotFoundException extends RuntimeException {
    public DeviceNotFoundException(String message) {
        super(message);
    }
}