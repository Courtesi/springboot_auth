package dev.wenslo.trueshotodds.repository;

import dev.wenslo.trueshotodds.entity.DeleteAccountToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface DeleteAccountTokenRepository extends JpaRepository<DeleteAccountToken, Long> {

    Optional<DeleteAccountToken> findByToken(String token);

    @Query("SELECT t FROM DeleteAccountToken t WHERE t.token = :token AND t.used = false AND t.expiresAt > :now")
    Optional<DeleteAccountToken> findValidToken(@Param("token") String token, @Param("now") LocalDateTime now);

    @Modifying
    @Query("DELETE FROM DeleteAccountToken t WHERE t.user.id = :userId")
    void deleteAllByUserId(@Param("userId") String userId);

    @Modifying
    @Query("DELETE FROM DeleteAccountToken t WHERE t.expiresAt < :cutoffTime")
    void deleteExpiredTokens(@Param("cutoffTime") LocalDateTime cutoffTime);

    @Query("SELECT COUNT(t) FROM DeleteAccountToken t WHERE t.user.id = :userId AND t.used = false AND t.expiresAt > :now")
    long countValidTokensForUser(@Param("userId") String userId, @Param("now") LocalDateTime now);
}