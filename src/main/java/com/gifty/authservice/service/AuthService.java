package com.gifty.authservice.service;

import com.gifty.authservice.exception.*;
import com.gifty.authservice.model.Admin;
import com.gifty.authservice.model.Customer;
import com.gifty.authservice.model.User;
import com.gifty.authservice.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

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
     * Kullanıcı giriş işlemini gerçekleştirir. Kullanıcı adı ve şifre doğrulanır.
     *
     * @param username Kullanıcının kullanıcı adı
     * @param rawPassword Kullanıcının şifresi
     * @return Doğrulanmış kullanıcı
     */
    public User login(String username, String rawPassword) {
        // Kullanıcı adı ile kullanıcıyı bul
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsCustomException("Invalid username."));

        // Şifreyi kontrol et
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new BadCredentialsCustomException("Invalid password.");
        }

        return user;
    }

    /**
     * Belirtilen cihaz için kullanıcıyı sistemden çıkarır.
     *
     * @param username Kullanıcının kullanıcı adı
     * @param deviceId Kullanıcının cihaz kimliği
     */
    public void logout(String username, String deviceId) {
        // Kullanıcıyı bul
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new SessionNotFoundException("User not found."));

        // Belirtilen cihaz için oturum var mı kontrol et
        if (!user.getDeviceTokens().containsKey(deviceId)) {
            throw new SessionNotFoundException("Session not found for the given device.");
        }

        // Cihazdaki token bilgisini kaldır
        user.getDeviceTokens().remove(deviceId);
        userRepository.save(user);
    }

    /**
     * Kullanıcıyı tüm cihazlardan sistemden çıkarır.
     *
     * @param username Kullanıcının kullanıcı adı
     */
    public void logoutFromAllDevices(String username) {
        // Kullanıcıyı bul
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new SessionNotFoundException("User not found."));

        // Tüm cihazlardaki tokenları temizle
        user.getDeviceTokens().clear();
        userRepository.save(user);
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
