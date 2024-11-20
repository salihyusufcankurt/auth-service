package com.gifty.authservice.model;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDateTime;

@Entity
@Table(name = "token_blacklist")
@Data
public class TokenBlacklist {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "token", nullable = false, unique = true)
    private String token; // Geçersiz kılınan token

    @Column(name = "added_at", nullable = false)
    private LocalDateTime addedAt; // Token'ın blacklist'e eklendiği zaman
}
