package com.gifty.authservice.controller;

import com.gifty.authservice.dto.LoginDTO;
import com.gifty.authservice.dto.RegisterDTO;
import com.gifty.authservice.model.User;
import com.gifty.authservice.service.AuthService;
import com.gifty.authservice.service.TokenService;
import com.gifty.authservice.util.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Kullanıcı işlemleri (kayıt, giriş ve çıkış) için controller.
 */
@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;
    private final TokenService tokenService;

    /**
     * Kullanıcı kaydı için endpoint.
     *
     * @param registerDTO Kullanıcı kayıt bilgilerini içeren DTO
     * @return Kayıt durumu
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterDTO registerDTO) {
        authService.register(registerDTO.getUsername(), registerDTO.getEmail(),
                registerDTO.getPassword(), registerDTO.getType());
        return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully.");
    }

    /**
     * Kullanıcı girişi için endpoint.
     *
     * @param loginDTO Kullanıcı giriş bilgilerini içeren DTO
     * @param request  HTTP isteği (IP adresini almak için kullanılıyor)
     * @return Access ve refresh token'larını döner
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginDTO loginDTO, HttpServletRequest request) {
        String clientIp = RequestUtils.getClientIp(request);
        String userAgent = RequestUtils.getUserAgent(request);

        // Eğer `userAgent` boş ise varsayılan bir değer ata
        if (userAgent == null || userAgent.isEmpty()) {
            userAgent = "Unknown"; // Varsayılan değer atanır
        }

        // Giriş yap ve tokenları üret
        Map<String, String> tokens = authService.login(
                loginDTO.getUsername(),
                loginDTO.getPassword(),
                loginDTO.getDeviceName(),
                clientIp,
                userAgent,
                loginDTO.getLocation()
        );
        return ResponseEntity.ok(tokens);
    }

    /**
     * Belirtilen cihaz için çıkış işlemi yapar.
     *
     * @param logoutData Çıkış için gerekli veriler (username, deviceId)
     * @return Çıkış durumu
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> logoutData) {
        authService.logout(logoutData.get("username"), logoutData.get("deviceName"));
        return ResponseEntity.ok("Logout successful.");
    }

    /**
     * Tüm cihazlardan çıkış işlemi yapar.
     *
     * @param logoutData Çıkış için gerekli veriler (username)
     * @return Çıkış durumu
     */
    @PostMapping("/logout-from-all-devices")
    public ResponseEntity<?> logoutFromAllDevices(@RequestBody Map<String, String> logoutData) {
        authService.logoutFromAllDevices(logoutData.get("username"));
        return ResponseEntity.ok("Logout from all devices successful.");
    }
}
