package dev.wenslo.trueshotodds.repository;

import dev.wenslo.trueshotodds.entity.User;
import dev.wenslo.trueshotodds.entity.UserStatus;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, String> {

    Optional<User> findByEmailIgnoreCase(String email);

    Optional<User> findByEmailVerificationToken(String token);

    Optional<User> findByStripeCustomerId(String stripeCustomerId);

    Optional<User> findByOauthProviderAndOauthId(String oauthProvider, String oauthId);

    boolean existsByEmailIgnoreCase(String email);

    @Modifying
    @Query("UPDATE User u SET u.lastLoginAt = :lastLoginAt, u.failedLoginAttempts = 0, u.accountLockedUntil = null WHERE u.id = :userId")
    void updateLastLoginAndResetFailedAttempts(@Param("userId") String userId, @Param("lastLoginAt") LocalDateTime lastLoginAt);

    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = u.failedLoginAttempts + 1 WHERE u.email = :email")
    void incrementFailedLoginAttempts(@Param("email") String email);

    @Modifying
    @Query("UPDATE User u SET u.accountLockedUntil = :lockoutTime WHERE u.email = :email")
    void lockUserAccount(@Param("email") String email, @Param("lockoutTime") LocalDateTime lockoutTime);

    @Modifying
    @Query("UPDATE User u SET u.emailVerified = true, u.status = :status, u.emailVerificationToken = null, u.emailVerificationTokenExpiresAt = null WHERE u.emailVerificationToken = :token")
    void verifyUserEmail(@Param("token") String token, @Param("status") UserStatus status);

    @Modifying
    @Query("UPDATE User u SET u.password = :password WHERE u.id = :userId")
    void updatePassword(@Param("userId") String userId, @Param("password") String password);
}