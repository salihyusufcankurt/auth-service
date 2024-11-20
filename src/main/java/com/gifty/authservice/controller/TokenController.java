package com.gifty.authservice.controller;

import com.gifty.authservice.service.TokenService;
import com.gifty.authservice.util.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Token işlemleri (access ve refresh token) için controller.
 */
@RestController
@RequestMapping("/token")
@RequiredArgsConstructor
public class TokenController {

    private final TokenService tokenService;

    /**
     * Refresh token kullanarak yeni bir access token üretir.
     *
     * @param refreshToken Refresh token
     * @param deviceId     Cihaz kimliği
     * @param request      HTTP isteği (IP adresini almak için kullanılıyor)
     * @return Yeni access token
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            @RequestHeader("Refresh-Token") String refreshToken,
            @RequestHeader("Device-Id") String deviceId,
            HttpServletRequest request) {
        String clientIp = RequestUtils.getClientIp(request);
        String newAccessToken = tokenService.refreshAccessToken(refreshToken, deviceId, clientIp);
        return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
    }

    /**
     * Access token geçerliliğini doğrular.
     *
     * @param accessToken Doğrulanacak access token (Authorization header'ında bulunur)
     * @return Token geçerli ise "valid: true", geçersiz ise "valid: false" döner.
     *
     * @apiNote Bu endpoint, mevcut bir access token'ın süresinin dolup dolmadığını veya geçersiz olup olmadığını kontrol etmek için kullanılır.
     *          Örneğin, bir frontend uygulaması access token'ı doğrulamadan önce bu endpoint'i çağırabilir.
     */
    @GetMapping("/validate")
    public ResponseEntity<?> validateAccessToken(@RequestHeader("Authorization") String accessToken) {
        boolean isValid = tokenService.validateAccessToken(accessToken);
        return ResponseEntity.ok(Map.of("valid", isValid));
    }

    @GetMapping("/blacklist-refresh-token")
    public ResponseEntity<?> blacklistRefreshToken(@RequestHeader("Authorization") String refreshToken) {
        try {
            // Refresh token'ı blacklist'e ekle
            tokenService.blacklistRefreshToken(refreshToken);

            // Başarılı yanıt döndür
            return ResponseEntity.ok(Map.of("status", "success", "message", "Refresh token blacklisted successfully."));
        } catch (Exception ex) {
            // Hata durumunda yanıt döndür
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "status", "error",
                    "message", ex.getMessage()
            ));
        }
    }


}
