package com.gifty.authservice.service;

import com.gifty.authservice.exception.InvalidTokenException;
import com.gifty.authservice.exception.SessionNotFoundException;
import com.gifty.authservice.exception.TokenExpiredException;
import com.gifty.authservice.exception.UnauthorizedAccessException;
import com.gifty.authservice.model.User;
import com.gifty.authservice.repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class TokenService {

    private final JwtUtil jwtUtil;
    private final UserRepository userRepository;

    /**
     * Kullanıcı için access ve refresh token üretir. Üretilen refresh token'ı veritabanına kaydeder.
     *
     * @param user      Kullanıcı bilgisi
     * @param deviceId  Kullanıcının cihaz kimliği
     * @param clientIp  Kullanıcının IP adresi
     * @return Access ve refresh token'larını içeren bir map döner
     */
    public Map<String, String> generateTokens(User user, String deviceId, String clientIp) {
        String accessToken = jwtUtil.generateAccessToken(user.getUsername(), Map.of("role", user.getType()));
        String refreshToken = jwtUtil.generateRefreshToken(user.getUsername());

        // Refresh token'ı veritabanına kaydet
        user.getDeviceTokens().put(deviceId, refreshToken);
        user.setLastUsedIp(clientIp);
        userRepository.save(user);

        return Map.of("accessToken", accessToken, "refreshToken", refreshToken);
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
        // Token doğrulama
        if (!jwtUtil.validateToken(refreshToken, false)) {
            throw new InvalidTokenException("The provided refresh token is invalid.");
        }

        // Refresh token'dan kullanıcı adı al
        String username = jwtUtil.getUsernameFromToken(refreshToken, false);
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new InvalidTokenException("User associated with this token does not exist."));

        // Kullanıcı oturum kontrolü
        if (!user.getDeviceTokens().containsKey(deviceId)) {
            throw new SessionNotFoundException("No active session found for the given device.");
        }

        // IP kontrolü
        if (user.getLastUsedIp() != null && !user.getLastUsedIp().equals(clientIp)) {
            throw new UnauthorizedAccessException("Access denied due to IP mismatch.");
        }

        // Cihaz eşleşmesi kontrolü
        if (!user.getDeviceTokens().get(deviceId).equals(refreshToken)) {
            throw new UnauthorizedAccessException("Access denied due to device mismatch.");
        }

        // Yeni access token üret ve döndür
        String newAccessToken = jwtUtil.generateAccessToken(username, Map.of("role", user.getType()));
        return newAccessToken;
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

}
