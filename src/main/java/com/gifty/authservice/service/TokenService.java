package com.gifty.authservice.service;

import com.gifty.authservice.exception.InvalidTokenException;
import com.gifty.authservice.exception.SessionNotFoundException;
import com.gifty.authservice.exception.TokenExpiredException;
import com.gifty.authservice.exception.UnauthorizedAccessException;
import com.gifty.authservice.model.Device;
import com.gifty.authservice.model.TokenBlacklist;
import com.gifty.authservice.model.User;
import com.gifty.authservice.repository.DeviceRepository;
import com.gifty.authservice.repository.TokenBlacklistRepository;
import com.gifty.authservice.repository.UserRepository;
import com.gifty.authservice.util.TokenEncryptionService;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;
    private final DeviceRepository deviceRepository;
    private final TokenEncryptionService tokenEncryptionService;
    private final TokenBlacklistRepository tokenBlacklistRepository;



    /**
     * Kullanıcı için access ve refresh token üretir. Üretilen refresh token'ı veritabanına kaydeder.
     *
     * @param user      Kullanıcı bilgisi
     * @param deviceId  Kullanıcının cihaz kimliği
     * @param clientIp  Kullanıcının IP adresi
     * @return Access ve refresh token'larını içeren bir map döner
     */
    public Map<String, String> generateTokens(User user, String deviceId, String clientIp) {
        try {
            String accessToken = jwtUtil.generateAccessToken(user.getUsername(), Map.of("role", user.getType()));
            String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

            // Refresh token'ı şifrele
            String encryptedRefreshToken = tokenEncryptionService.encrypt(refreshToken);

            // Cihazı kaydet veya güncelle
            Device device = deviceRepository.findByUserIdAndDeviceName(user.getId(), deviceId)
                    .orElse(new Device());
            device.setUser(user);
            device.setDeviceName(deviceId);
            device.setIpAddress(clientIp);
            device.setLastActive(LocalDateTime.now());
            device.setRefreshToken(encryptedRefreshToken); // Şifrelenmiş token'ı kaydet
            deviceRepository.save(device);

            // Access ve refresh tokenlarını döndür
            return Map.of(
                    "accessToken", accessToken,
                    "refreshToken", refreshToken // Şifrelenmemiş token döndürülür
            );
        } catch (Exception e) {
            throw new RuntimeException("Error generating tokens: " + e.getMessage());
        }
    }

    /**
     * Refresh token kullanarak yeni bir access token üretir.
     *
     * @param refreshToken Refresh token
     * @param deviceId     Kullanıcının cihaz kimliği
     * @param clientIp     Kullanıcının IP adresi
     * @return Yeni access token
     */
    public String refreshAccessToken(String refreshToken, String deviceId, String clientIp) {
        try {
            validateRefreshToken(refreshToken);

            // Kullanıcı ve cihaz doğrulaması
            String username = jwtUtil.getUsernameFromToken(refreshToken, false);
            User user = userRepository.findByUsername(username)
                    .orElseThrow(() -> new InvalidTokenException("User associated with this token does not exist."));

            Device device = deviceRepository.findByUserIdAndDeviceName(user.getId(), deviceId)
                    .orElseThrow(() -> new SessionNotFoundException("No active session found for the given device."));

            // IP adresi doğrulama
            if (!device.getIpAddress().equals(clientIp)) {
                throw new UnauthorizedAccessException("IP address mismatch detected.");
            }

            // Yeni access token üret ve döndür
            return jwtUtil.generateAccessToken(username, Map.of("role", user.getType()));
        } catch (Exception e) {
            throw new RuntimeException("Error refreshing access token: " + e.getMessage());
        }
    }

    /**
     * Access token'ın geçerliliğini kontrol eder.
     *
     * @param accessToken Doğrulanacak access token
     * @return Token geçerli ise true, geçersiz veya süresi dolmuş ise false
     * @throws InvalidTokenException Eğer token formatı veya yapısı geçerli değilse fırlatılır.
     * @throws TokenExpiredException Eğer token süresi dolmuşsa fırlatılır.
     */
    public boolean validateAccessToken(String accessToken) {
        try {
            // Token'ın imzasını ve yapısını doğrula
            if (!jwtUtil.validateToken(accessToken, true)) {
                throw new InvalidTokenException("The provided access token is invalid.");
            }

            // Token'ın süresinin geçip geçmediğini kontrol et
            if (jwtUtil.isTokenExpired(accessToken, true)) {
                throw new TokenExpiredException("The provided access token has expired.");
            }

            // Token'dan iddia (claims) bilgilerini al
            Claims claims = jwtUtil.getClaimsFromToken(accessToken, true);

            // İş kuralları doğrulaması (örneğin, role kontrolü)
            String role = claims.get("role", String.class);
            if (role == null || role.isEmpty()) {
                throw new InvalidTokenException("The access token does not contain a valid role.");
            }

            // Token geçerli
            return true;

        } catch (InvalidTokenException | TokenExpiredException ex) {
            // Belirli hatalar için false döner
            return false;

        } catch (Exception ex) {
            // Diğer beklenmeyen hatalar için false döner
            return false;
        }
    }
    /**
     * Refresh token'ın geçerliliğini kontrol eder.
     *
     * @param refreshToken Doğrulanacak token
     */
    public void validateRefreshToken(String refreshToken) {
        if (isRefreshTokenBlacklisted(refreshToken)) {
            throw new InvalidTokenException("Refresh token has been blacklisted.");
        }
        if (!jwtUtil.validateToken(refreshToken, false)) {
            throw new TokenExpiredException("Refresh token is invalid or expired.");
        }
    }

    /**
     * Refresh token'ı blacklist'e ekler.
     *
     * @param refreshToken Blacklist'e eklenecek token
     */
    public void blacklistRefreshToken(String refreshToken) {
        TokenBlacklist blacklist = new TokenBlacklist();
        blacklist.setToken(refreshToken);
        blacklist.setAddedAt(LocalDateTime.now());
        tokenBlacklistRepository.save(blacklist);
    }

    /**
     * Refresh token'ın blacklist'te olup olmadığını kontrol eder.
     *
     * @param refreshToken Kontrol edilecek token
     * @return Token geçerli mi
     */
    public boolean isRefreshTokenBlacklisted(String refreshToken) {
        return tokenBlacklistRepository.findByToken(refreshToken).isPresent();
    }

    /**
     * Belirli bir cihaz için refresh token'ı geçersiz kılar.
     *
     * @param deviceName Cihaz adı
     * @param user Kullanıcı bilgisi
     */
    @Transactional
    public void invalidateRefreshToken(String deviceName, User user) {
        Device device = deviceRepository.findByUserIdAndDeviceName(user.getId(), deviceName)
                .orElseThrow(() -> new IllegalArgumentException("Device not found"));

        // Refresh token'ı temizle
        device.setRefreshToken(null);
        deviceRepository.save(device);
    }



}
