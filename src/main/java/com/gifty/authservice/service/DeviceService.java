// src/main/java/com/gifty/authservice/service/DeviceService.java

package com.gifty.authservice.service;

import com.gifty.authservice.exception.SessionNotFoundException;
import com.gifty.authservice.model.Device;
import com.gifty.authservice.model.User;
import com.gifty.authservice.repository.DeviceRepository;
import com.gifty.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

/**
 * Cihazlarla ilgili iş mantığını içeren servis sınıfı.
 */
@Service
@RequiredArgsConstructor
public class DeviceService {

    private final DeviceRepository deviceRepository;
    private final UserRepository userRepository;
    private final TokenService tokenService;

    /**
     * Cihazı kaydeder veya mevcutsa günceller.
     *
     * @param userId     Kullanıcı kimliği
     * @param deviceName Cihaz adı
     * @param ipAddress  IP adresi
     * @param userAgent  Kullanıcı aracı bilgisi
     * @param location   Konum bilgisi
     * @return Kaydedilen veya güncellenen cihaz
     */
    @Transactional
    public Device registerOrUpdateDevice(UUID userId, String deviceName, String ipAddress, String userAgent, String location, String refreshToken) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("Kullanıcı bulunamadı"));

        Optional<Device> existingDevice = deviceRepository.findByUserIdAndDeviceName(userId, deviceName);

        Device device;
        if (existingDevice.isPresent()) {
            device = existingDevice.get();
            device.setIpAddress(ipAddress);
            device.setUserAgent(userAgent);
            device.setLocation(location);
            device.setLastActive(LocalDateTime.now());
            device.setRefreshToken(refreshToken); // Refresh token'ı güncelle
        } else {
            device = new Device();
            device.setUser(user);
            device.setDeviceName(deviceName);
            device.setIpAddress(ipAddress);
            device.setUserAgent(userAgent);
            device.setLocation(location);
            device.setLastActive(LocalDateTime.now());
            device.setRefreshToken(refreshToken); // Yeni cihaz için refresh token ekle
            user.getDevices().add(device);
        }

        return deviceRepository.save(device);
    }


    /**
     * Kullanıcının belirli bir cihazdan çıkış yapmasını sağlar.
     */
    @Transactional
    public void logout(String username, String deviceName) {
        // Kullanıcıyı bul
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new SessionNotFoundException("User not found."));

        if (deviceName == null || deviceName.isEmpty()) {
            throw new IllegalArgumentException("Device name cannot be null or empty");
        }
        // Cihazı bul
        Device device = user.getDevices().stream()
                .filter(d -> d.getDeviceName().equals(deviceName))
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException("Belirtilen cihaz bulunamadı"));

        // Refresh token'ı blacklist'e ekle
        if (device.getRefreshToken() != null) {
            tokenService.blacklistRefreshToken(device.getRefreshToken());
        }
        // Cihazı kullanıcı cihaz listesinden kaldır
        user.getDevices().remove(device);



        // Kullanıcıyı kaydet
        userRepository.save(user);
    }

    /**
     * Kullanıcının tüm cihazlarını siler.
     */
    @Transactional
    public void logoutFromAllDevices(String username) {
        // Kullanıcıyı bul
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new SessionNotFoundException("User not found."));

        for (Device device : user.getDevices()) {
            tokenService.invalidateRefreshToken(device.getDeviceName(), user);
        }

        // Tüm cihazları kullanıcıdan kaldır
        user.getDevices().clear();

        // Veri tabanından tüm cihazları sil
        deviceRepository.deleteAll(user.getDevices());

        // Kullanıcıyı kaydet
        userRepository.save(user);
    }
}
