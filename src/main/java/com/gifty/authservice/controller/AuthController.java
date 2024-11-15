package com.gifty.authservice.controller;

import com.gifty.authservice.exception.*;
import com.gifty.authservice.service.AuthService;
import com.gifty.authservice.service.JwtUtil;
import com.gifty.authservice.util.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {

    @Autowired
    private final AuthService authService;
    private final JwtUtil jwtUtil; // JwtUtil burada dependency injection ile geliyor.


    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody Map<String, String> registerData) {
        try {
            authService.register(registerData);
            return ResponseEntity.status(HttpStatus.CREATED).body("User registered successfully.");
        } catch (UserAlreadyExistsException ex) {
            // Kullanıcı zaten mevcutsa
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Conflict");
            errorResponse.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.CONFLICT).body(errorResponse);
        } catch (InvalidInputException ex) {
            // Geçersiz giriş verisi
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Bad Request");
            errorResponse.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        }  catch (Exception ex) {
            // Beklenmeyen hata
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Internal Server Error");
            errorResponse.put("message", "An unexpected error occurred. Please try again later.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody Map<String, String> loginData, HttpServletRequest request) {
        try {
            if (loginData == null || loginData.get("username") == null || loginData.get("password") == null || loginData.get("deviceId") == null) {
                throw new InvalidInputException("Username, password, and deviceId must not be empty.");
            }

            String username = loginData.get("username").trim();
            String password = loginData.get("password").trim();
            String deviceId = loginData.get("deviceId").trim();

            // AuthService'deki login metoduna istekle birlikte HttpServletRequest'i gönderiyoruz
            Map<String, String> tokens = authService.login(username, password, deviceId, request);

            return ResponseEntity.ok(tokens);
        } catch (InvalidInputException ex) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Bad Request");
            errorResponse.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(errorResponse);
        } catch (BadCredentialsCustomException ex) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Unauthorized");
            errorResponse.put("message", ex.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(errorResponse);
        } catch (Exception ex) {
            Map<String, String> errorResponse = new HashMap<>();
            errorResponse.put("error", "Internal Server Error");
            errorResponse.put("message", "An unexpected error occurred.");
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorResponse);
        }
    }

//todo refreh tokenda client ip device id ve refresh tokenı headerda istiyor bu makul mü? client ip yi nereden çekip atacağım?
@PostMapping("/refresh-token")
public ResponseEntity<?> refreshToken(
        @RequestHeader(value = "Refresh-Token", required = false) String refreshTokenHeader,
        @RequestHeader(value = "Device-Id", required = false) String deviceId,
        HttpServletRequest request) {
    try {
        // Refresh token'ı header'dan al
        if (refreshTokenHeader == null || !refreshTokenHeader.startsWith("Bearer ")) {
            throw new InvalidInputException("Invalid or missing refresh token.");
        }
        String refreshToken = refreshTokenHeader.substring(7);
        if (deviceId == null || deviceId.trim().isEmpty()) {
            throw new InvalidInputException("Device ID must not be empty.");
        }

        // Client IP'yi al
        String clientIp = RequestUtils.getClientIp(request);

        // Refresh token kontrolü
        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new InvalidInputException("Refresh token and Device Id is required.");
        }

        // Yeni access token al
        String newAccessToken = authService.refreshAccessToken(refreshToken, clientIp, deviceId);

        // Response
        Map<String, String> response = new HashMap<>();
        response.put("accessToken", newAccessToken);
        return ResponseEntity.ok(response);
    }catch (SessionNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND)
                .body(Map.of("error", "Session Not Found", "message", ex.getMessage()));
    }
    catch (UnauthorizedAccessException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Unauthorized", "message", ex.getMessage()));
    } catch (InvalidTokenException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Invalid Token", "message", ex.getMessage()));
    } catch (TokenExpiredException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("error", "Token Expired", "message", ex.getMessage()));
    } catch (InvalidInputException ex) {
        return ResponseEntity.badRequest()
                .body(Map.of("error", "Bad Request", "message", ex.getMessage()));
    } catch (Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body(Map.of("error", "Internal Server Error", "message", "An unexpected error occurred."));
    }
}


    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String accessToken,
                                    @RequestBody Map<String, String> logoutData) {
        try {
            // Access token kontrolü
            if (accessToken == null || accessToken.trim().isEmpty() || !accessToken.startsWith("Bearer ")) {
                throw new UnauthorizedAccessException("Invalid or missing access token.");
            }

            String token = accessToken.substring(7); // "Bearer " kısmını kes
            if (!jwtUtil.validateToken(token, true)) {
                throw new InvalidTokenException("Access token is invalid or expired.");
            }

            // Eksik parametre kontrolü
            String username = logoutData.get("username");
            String deviceId = logoutData.get("deviceId");

            if (username == null || username.trim().isEmpty() || deviceId == null || deviceId.trim().isEmpty()) {
                throw new InvalidInputException("Username and deviceId must be provided and must not be empty.");
            }


            // Logout işlemini çağır
            authService.logout(username, deviceId);
            return ResponseEntity.ok(Map.of("message", "Logout successful."));
        } catch (SessionNotFoundException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(Map.of("error", "Session Not Found", "message", ex.getMessage()));
        }catch (InvalidInputException ex) {
            return ResponseEntity.badRequest().body(Map.of("error", "Bad Request", "message", ex.getMessage()));
        } catch (UnauthorizedAccessException ex) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(Map.of("error", "Unauthorized", "message", ex.getMessage()));
        } catch (BadCredentialsCustomException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "Not Found", "message", ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal Server Error", "message", "An unexpected error occurred."));
        }
    }


    @PostMapping("/logout-from-all-devices")
    public ResponseEntity<?> logoutFromAllDevices(@RequestBody Map<String, String> logoutData) {
        try {
            String username = logoutData.get("username");

            if (username == null ) {
                return ResponseEntity.badRequest().body(Map.of("error", "Bad Request", "message", "Username and deviceId are required."));
            }

            authService.logoutFromAllDevices(username);
            return ResponseEntity.ok(Map.of("message", "Logout successful."));
        } catch (BadCredentialsCustomException ex) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(Map.of("error", "Not Found", "message", ex.getMessage()));
        } catch (Exception ex) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of("error", "Internal Server Error", "message", "An unexpected error occurred."));
        }
    }

    @GetMapping("/success")
    public ResponseEntity<String> googleLoginSuccess() {
        return ResponseEntity.ok("Google Login Successful!");
    }
}