package com.gifty.authservice.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Hata yönetimi için merkezi bir sınıf.
 * Tüm istisnalar burada ele alınır ve standart bir yanıt formatı döndürülür.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Genel istisnalar için handler.
     * Beklenmeyen hatalar bu metod tarafından ele alınır.
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<?> handleGenericException(Exception ex) {
        return createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "INTERNAL_SERVER_ERROR", ex.getMessage());
    }

    /**
     * Oturum bulunamadığında oluşan istisnalar için handler.
     */
    @ExceptionHandler(SessionNotFoundException.class)
    public ResponseEntity<?> handleSessionNotFoundException(SessionNotFoundException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "SESSION_NOT_FOUND", ex.getMessage());
    }

    /**
     * Kullanıcı adı veya şifre hatalı olduğunda oluşan istisnalar için handler.
     */
    @ExceptionHandler(BadCredentialsCustomException.class)
    public ResponseEntity<?> handleBadCredentialsException(BadCredentialsCustomException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "BAD_CREDENTIALS", ex.getMessage());
    }

    /**
     * Kullanıcı zaten mevcut olduğunda oluşan istisnalar için handler.
     */
    @ExceptionHandler(UserAlreadyExistsException.class)
    public ResponseEntity<?> handleUserAlreadyExistsException(UserAlreadyExistsException ex) {
        return createErrorResponse(HttpStatus.CONFLICT, "USER_ALREADY_EXISTS", ex.getMessage());
    }

    /**
     * Geçersiz girişler için handler.
     */
    @ExceptionHandler(InvalidInputException.class)
    public ResponseEntity<?> handleInvalidInputException(InvalidInputException ex) {
        return createErrorResponse(HttpStatus.BAD_REQUEST, "INVALID_INPUT", ex.getMessage());
    }

    /**
     * Geçersiz token durumunda oluşan istisnalar için handler.
     */
    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<?> handleInvalidTokenException(InvalidTokenException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "INVALID_TOKEN", ex.getMessage());
    }

    /**
     * Süresi dolmuş token durumunda oluşan istisnalar için handler.
     */
    @ExceptionHandler(TokenExpiredException.class)
    public ResponseEntity<?> handleTokenExpiredException(TokenExpiredException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "TOKEN_EXPIRED", ex.getMessage());
    }

    /**
     * Blacklist'e alınmış token durumunda oluşan istisnalar için handler.
     */
    @ExceptionHandler(TokenBlacklistException.class)
    public ResponseEntity<?> handleTokenBlacklistException(TokenBlacklistException ex) {
        return createErrorResponse(HttpStatus.FORBIDDEN, "TOKEN_BLACKLISTED", ex.getMessage());
    }

    /**
     * Geçersiz refresh token durumunda oluşan istisnalar için handler.
     */
    @ExceptionHandler(RefreshTokenInvalidException.class)
    public ResponseEntity<?> handleRefreshTokenInvalidException(RefreshTokenInvalidException ex) {
        return createErrorResponse(HttpStatus.UNAUTHORIZED, "REFRESH_TOKEN_INVALID", ex.getMessage());
    }

    /**
     * Cihaz bulunamadığında oluşan istisnalar için handler.
     */
    @ExceptionHandler(DeviceNotFoundException.class)
    public ResponseEntity<?> handleDeviceNotFoundException(DeviceNotFoundException ex) {
        return createErrorResponse(HttpStatus.NOT_FOUND, "DEVICE_NOT_FOUND", ex.getMessage());
    }

    /**
     * Hata yanıtını standart bir formatta döndürmek için yardımcı metod.
     *
     * @param status     HTTP durumu
     * @param errorCode  Hata kodu
     * @param message    Hata mesajı
     * @return Hata yanıtı
     */
    private ResponseEntity<Map<String, Object>> createErrorResponse(HttpStatus status, String errorCode, String message) {
        Map<String, Object> errorResponse = Map.of(
                "timestamp", LocalDateTime.now(),
                "status", status.value(),
                "error", errorCode,
                "message", message
        );
        return ResponseEntity.status(status).body(errorResponse);
    }
}
