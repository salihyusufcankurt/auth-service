package com.gifty.authservice.service;

import com.gifty.authservice.exception.*;
import com.gifty.authservice.model.Admin;
import com.gifty.authservice.model.Customer;
import com.gifty.authservice.model.Device;
import com.gifty.authservice.model.User;
import com.gifty.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;

/**
 * Kullanıcıların giriş, kayıt ve oturum işlemlerini yöneten servis.
 */
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final DeviceService deviceService;
    private final TokenService tokenService;



    /**
     * Kullanıcı kayıt işlemini gerçekleştirir. Kullanıcı adı, e-posta, şifre ve kullanıcı tipi doğrulanır.
     * Ardından kullanıcı veritabanına kaydedilir.
     *
     * @param username  Kullanıcının kullanıcı adı
     * @param email     Kullanıcının e-posta adresi
     * @param password  Kullanıcının şifresi
     * @param type  Kullanıcının türü (ADMIN veya CUSTOMER)
     */
    public void register(String username, String email, String password, String type) {
        // Kullanıcı adı veya e-posta kontrolü
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            throw new UserAlreadyExistsException("A user with this username or email already exists.");
        }

        // Şifre kontrolü
        if (!isValidPassword(password)) {
            throw new InvalidInputException("Password does not meet the required criteria.");
        }

        // Kullanıcı tipi kontrolü
        if (!type.equalsIgnoreCase("ADMIN") && !type.equalsIgnoreCase("CUSTOMER")) {
            throw new InvalidInputException("Invalid user type specified.");
        }

        // Kullanıcı oluşturma ve kaydetme
        User user = createUser(username, email, password, type);
        userRepository.save(user);
    }

    /**
     * Kullanıcı giriş işlemini gerçekleştirir ve cihaz bilgilerini kaydeder veya günceller.
     *
     * @param username    Kullanıcı adı
     * @param rawPassword Şifre
     * @param deviceName  Cihaz adı
     * @param ipAddress   IP adresi
     * @param userAgent   Kullanıcı aracı bilgisi
     * @param location    Coğrafi konum bilgisi
     * @return Giriş yapan kullanıcı bilgisi
     */
    @Transactional
    public Map<String, String> login(String username, String rawPassword, String deviceName, String ipAddress, String userAgent, String location) {
        // Kullanıcıyı bul ve doğrula
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalArgumentException("Geçersiz kullanıcı adı veya şifre"));

        // Şifre doğrulaması
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new IllegalArgumentException("Geçersiz kullanıcı adı veya şifre");
        }

        // Tokenları oluştur
        Map<String, String> tokens = tokenService.generateTokens(user, deviceName, ipAddress);
        String refreshToken = tokens.get("refreshToken");

        // Cihaz bilgilerini kaydet veya güncelle ve refreshToken'ı ekle
        deviceService.registerOrUpdateDevice(user.getId(), deviceName, ipAddress, userAgent, location, refreshToken);

        return tokens; // Access ve Refresh Token'ları döndür
    }

    /**
     * Belirtilen cihaz için kullanıcıyı sistemden çıkarır.
     *
     * @param username Kullanıcının kullanıcı adı
     * @param deviceName Kullanıcının cihaz adı
     */
    @Transactional
    public void logout(String username, String deviceName) {
        deviceService.logout(username, deviceName); // Cihaz çıkışını DeviceService üzerinden yönet
    }

    /**
     * Kullanıcıyı tüm cihazlardan sistemden çıkarır.
     *
     * @param username Kullanıcının kullanıcı adı
     */
    @Transactional
    public void logoutFromAllDevices(String username) {
        deviceService.logoutFromAllDevices(username); // Tüm cihazlardan çıkışı DeviceService üzerinden yönet
    }

    /**
     * Kullanıcı oluşturur ve türüne göre (Admin veya Customer) gerekli alanları doldurur.
     *
     * @param username Kullanıcı adı
     * @param email    Kullanıcı e-postası
     * @param password Kullanıcı şifresi
     * @param userType Kullanıcı türü
     * @return Oluşturulan kullanıcı
     */
    private User createUser(String username, String email, String password, String userType) {
        if (userType.equalsIgnoreCase("ADMIN")) {
            Admin admin = new Admin();
            admin.setUsername(username);
            admin.setEmail(email);
            admin.setPassword(passwordEncoder.encode(password));
            return admin;
        } else {
            Customer customer = new Customer();
            customer.setUsername(username);
            customer.setEmail(email);
            customer.setPassword(passwordEncoder.encode(password));
            return customer;
        }
    }

    /**
     * Şifre kriterlerini kontrol eder (ör. minimum uzunluk).
     *
     * @param password Kontrol edilecek şifre
     * @return Şifrenin geçerli olup olmadığını döner
     */
    private boolean isValidPassword(String password) {
        return password.length() >= 8;
    }
}
