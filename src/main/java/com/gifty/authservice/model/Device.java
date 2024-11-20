package com.gifty.authservice.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;
import java.util.UUID;

/**
 * Kullanıcı cihazlarını temsil eden model.
 */
@Data
@Entity
@Table(name = "devices")
public class Device {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private UUID id; // Cihazın benzersiz kimliği.

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user; // Cihazın bağlı olduğu kullanıcı.

    @Column(name = "device_name", nullable = false)
    private String deviceName; // Cihaz adı veya tarayıcı bilgisi.

    @Column(name = "ip_address", nullable = false)
    private String ipAddress; // Cihazın IP adresi.

    @Column(name = "user_agent", nullable = true)
    private String userAgent; // Cihazın tarayıcı ve işletim sistemi bilgisi.

    @Column(name = "location")
    private String location; // Cihazın coğrafi konumu (isteğe bağlı).

    @Column(name = "last_active", nullable = false)
    private LocalDateTime lastActive; // Cihazın son aktif olduğu tarih ve saat.

    @Column(name = "refresh_token", nullable = true, length = 2048) // Refresh token uzunluğu için ayarlandı
    private String refreshToken; // Refresh token'ı saklama alanı

}
