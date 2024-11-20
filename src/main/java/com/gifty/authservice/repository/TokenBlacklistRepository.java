package com.gifty.authservice.repository;

import com.gifty.authservice.model.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {
    Optional<TokenBlacklist> findByToken(String token); // Token'ın blacklist'te olup olmadığını kontrol eder
}
