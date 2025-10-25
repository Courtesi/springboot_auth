package dev.wenslo.trueshotodds.repository;

import dev.wenslo.trueshotodds.entity.UserPreferences;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserPreferencesRepository extends JpaRepository<UserPreferences, Long> {

    Optional<UserPreferences> findByUserId(String userId);

    boolean existsByUserId(String userId);
}