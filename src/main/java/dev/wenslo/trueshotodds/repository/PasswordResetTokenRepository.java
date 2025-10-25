package dev.wenslo.trueshotodds.repository;

import dev.wenslo.trueshotodds.entity.PasswordResetToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface PasswordResetTokenRepository extends JpaRepository<PasswordResetToken, Long> {

    Optional<PasswordResetToken> findByTokenAndUsedFalse(String token);

    List<PasswordResetToken> findByUserIdAndUsedFalse(String userId);

    @Modifying
    @Query("UPDATE PasswordResetToken p SET p.used = true, p.usedAt = :usedAt WHERE p.id = :tokenId")
    void markTokenAsUsed(@Param("tokenId") Long tokenId, @Param("usedAt") LocalDateTime usedAt);

    @Modifying
    @Query("UPDATE PasswordResetToken p SET p.used = true WHERE p.user.id = :userId AND p.used = false")
    void invalidateAllUserTokens(@Param("userId") String userId);

    @Modifying
    @Query("DELETE FROM PasswordResetToken p WHERE p.expiresAt < :now")
    void deleteExpiredTokens(@Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM PasswordResetToken p WHERE p.user.id = :userId")
    void deleteAllByUserId(@Param("userId") String userId);
}