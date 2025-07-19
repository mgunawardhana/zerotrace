package com.zerotrace.repository;

import com.zerotrace.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    Optional<User> findByEmailAndAccountStatus(String email, User.AccountStatus status);

    Optional<User> findByEmailVerificationToken(String token);

    Optional<User> findByPasswordResetToken(String token);

    @Query("SELECT u FROM User u WHERE u.accountLockedUntil IS NOT NULL AND u.accountLockedUntil < :now")
    List<User> findUsersToUnlock(@Param("now") LocalDateTime now);

    @Query("SELECT u FROM User u WHERE u.lastPasswordChange < :date")
    List<User> findUsersWithOldPasswords(@Param("date") LocalDateTime date);

    @Query("SELECT u FROM User u WHERE u.lastActivity < :date AND u.accountStatus = 'ACTIVE'")
    List<User> findInactiveUsers(@Param("date") LocalDateTime date);

    @Modifying
    @Query("UPDATE User u SET u.failedLoginAttempts = 0, u.accountLockedUntil = null WHERE u.id = :userId")
    void resetFailedLoginAttempts(@Param("userId") Long userId);

    @Modifying
    @Query("UPDATE User u SET u.lastActivity = :now WHERE u.id = :userId")
    void updateLastActivity(@Param("userId") Long userId, @Param("now") LocalDateTime now);

    @Query("SELECT COUNT(u) FROM User u WHERE u.createdByIp = :ip AND u.createdDate > :since")
    long countRecentRegistrationsByIp(@Param("ip") String ip, @Param("since") LocalDateTime since);
}