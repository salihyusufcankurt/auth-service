package com.gifty.authservice.service;

import com.gifty.authservice.exception.*;
import com.gifty.authservice.model.Admin;
import com.gifty.authservice.model.Customer;
import com.gifty.authservice.model.User;
import com.gifty.authservice.repository.UserRepository;
import com.gifty.authservice.util.RequestUtils;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtUtil jwtUtil;
    private final PasswordEncoder passwordEncoder;

    public User registerUser(User user) {
        // Kullanıcının şifresini hashleyerek kaydediyoruz
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepository.save(user);
    }

    public void register(Map<String, String> registerData) {
        System.out.println("Register işlemi başladı: " + registerData);

        String username = registerData.get("username");
        String email = registerData.get("email");
        String type = registerData.get("type");

        // Kullanıcı adı veya e-posta zaten mevcutsa hata fırlat
        if (userRepository.existsByUsername(username) || userRepository.existsByEmail(email)) {
            System.out.println("hata1: " + registerData);

            throw new UserAlreadyExistsException("A user with this username or email already exists.");
        }

        // Şifre politikası kontrolü
        String password = registerData.get("password");
        if (!isValidPassword(password)) {
            System.out.println("hata2: " + registerData);
            throw new InvalidInputException("Password does not meet the required criteria.");
        }
        if (!type.equalsIgnoreCase("ADMIN") && !type.equalsIgnoreCase("CUSTOMER")) {
            System.out.println("hata3: " + registerData);
            throw new InvalidInputException("Invalid user type specified.");
        }


        // Kullanıcı oluşturma
        switch (type.toUpperCase()) {
            case "ADMIN":
                Admin admin = new Admin();
                admin.setAdminSpecificField("Some admin-specific data");
                admin.setUsername(username);
                admin.setEmail(email);
                admin.setPassword(passwordEncoder.encode(password));
                userRepository.save(admin);
                System.out.println("admin oluşturuldu: " + registerData);
                break;
            case "CUSTOMER":
                Customer customer = new Customer();
                customer.setCustomerSpecificField("Some customer-specific data");
                customer.setUsername(username);
                customer.setEmail(email);
                customer.setPassword(passwordEncoder.encode(password));
                userRepository.save(customer);
                System.out.println("customer oluşturuldu: " + registerData);
                break;
            default:
                throw new InvalidInputException("Invalid user type specified.");
        }

    }

    private boolean isValidPassword(String password) {
        // Şifre uzunluğu ve diğer kurallar
        return password.length() >= 8;
    }


    public Map<String, String> login(String username, String rawPassword, String deviceId, HttpServletRequest request) {
        String clientIp = RequestUtils.getClientIp(request); // İstemci IP'sini al

        // Kullanıcı adı veya şifre boş mu kontrolü
        if (username == null || username.trim().isEmpty() || rawPassword == null || rawPassword.trim().isEmpty()) {
            throw new InvalidInputException("Username and password must not be empty.");
        }
        //todo device id çekilemedi hatası oluştur

        // Kullanıcıyı veritabanında arıyoruz
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsCustomException("Invalid username."));

        // Şifre kontrolü
        if (!passwordEncoder.matches(rawPassword, user.getPassword())) {
            throw new BadCredentialsCustomException("Invalid password.");
        }
        // deviceId kontrolü
        if (deviceId == null || deviceId.trim().isEmpty()) {
            throw new InvalidInputException("Device ID must be provided and must not be empty.");
        }

        // Kullanıcı cihazını ekle veya güncelle
        if (!user.getDeviceTokens().containsKey(deviceId)) {
            user.getDeviceTokens().put(deviceId, null); // Refresh token daha sonra atanabilir
        }

        // Kullanıcının son kullanılan IP adresini güncelle
        user.setLastUsedIp(clientIp); // İlk girişte IP kaydediliyor.
        userRepository.save(user);

        // Kullanıcı doğrulandı, JWT token oluşturuyoruz
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getType());

        String accessToken = jwtUtil.generateAccessToken(username, claims);
        String refreshToken = jwtUtil.generateRefreshToken(username);

        // Refresh token'ı kullanıcı cihazına kaydet
        user.getDeviceTokens().put(deviceId, refreshToken);
        userRepository.save(user);

        Map<String, String> tokens = new HashMap<>();
        tokens.put("accessToken", accessToken);
        tokens.put("refreshToken", refreshToken);
        return tokens;

    }

    public void logout(String username, String deviceId) {
        // Kullanıcıyı bul
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsCustomException("User not found."));

        // Belirtilen cihaz için token olup olmadığını kontrol et
        if (!user.getDeviceTokens().containsKey(deviceId)) {
            throw new SessionNotFoundException("Session not found for the given device.");
        }

        // Cihazdaki token bilgisini kaldır
        user.getDeviceTokens().remove(deviceId);
        userRepository.save(user);
    }


    public void logoutFromAllDevices(String username) {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new BadCredentialsCustomException("User not found."));
        user.getDeviceTokens().clear();
        userRepository.save(user);
    }



    public String refreshAccessToken(String refreshToken, String clientIp, String deviceId) {
        // Refresh token geçerli mi kontrol et
        if (!jwtUtil.validateToken(refreshToken, false)) {
            throw new InvalidTokenException("The provided refresh token is invalid.");
        }

        // Refresh token süresi dolmuş mu kontrol et
        if (jwtUtil.isTokenExpired(refreshToken, false)) {
            throw new TokenExpiredException("Refresh token has expired.");
        }

        // Refresh token'dan kullanıcı bilgilerini al
        String username = jwtUtil.getUsernameFromToken(refreshToken, false);

        // Kullanıcıyı veritabanından kontrol et
        User user = userRepository.findByUsername(username)
                .orElseThrow(() -> new InvalidTokenException("User associated with this token does not exist."));

        // Kullanıcı logout olmuş mu kontrol et
        if (!user.getDeviceTokens().containsKey(deviceId)) {
            throw new SessionNotFoundException("No active session found for the given device.");
        }
        // IP adresi kontrolü
        if (user.getLastUsedIp() != null && !clientIp.equals(user.getLastUsedIp())) {
            System.out.println(clientIp);
            System.out.println(user.getLastUsedIp());

            throw new UnauthorizedAccessException("Access denied due to IP mismatch.");
        }

        // Cihaz eşleşmesi kontrolü
        if (!user.getDeviceTokens().containsKey(deviceId) ||
                !user.getDeviceTokens().get(deviceId).equals(refreshToken)) {
            throw new UnauthorizedAccessException("Access denied due to device mismatch.");
        }

        // Refresh token rotasyonu
        String newRefreshToken = jwtUtil.generateRefreshToken(username);
        user.getDeviceTokens().put(deviceId, newRefreshToken);
        user.setLastUsedIp(clientIp);
        userRepository.save(user);

        // Yeni access token oluşturma
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", user.getType());

        return jwtUtil.generateAccessToken(username, claims);
    }


}
