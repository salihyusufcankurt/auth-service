package com.gifty.authservice.repository;

import com.gifty.authservice.model.Device;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Cihazlarla ilgili veri tabanı işlemlerini yöneten repository.
 */
public interface DeviceRepository extends JpaRepository<Device, UUID> {

    /**
     * Kullanıcı ID ve cihaz adıyla eşleşen bir cihazı döner.
     *
     * @param userId Kullanıcının kimliği.
     * @param deviceName Cihaz adı.
     * @return Cihaz bilgisi.
     */
    Optional<Device> findByUserIdAndDeviceName(UUID userId, String deviceName);
}
