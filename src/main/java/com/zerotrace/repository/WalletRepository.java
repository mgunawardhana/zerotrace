package com.zerotrace.repository;

import com.zerotrace.entity.Wallet;
import com.zerotrace.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface WalletRepository extends JpaRepository<Wallet, Long> {

    List<Wallet> findByUserAndWalletStatus(User user, Wallet.WalletStatus status);

    List<Wallet> findByUser(User user);

    Optional<Wallet> findByWalletAddress(String walletAddress);

    boolean existsByWalletAddress(String walletAddress);

    Optional<Wallet> findByIdAndUser(Long id, User user);

    @Query("SELECT w FROM Wallet w WHERE w.user = :user AND w.currencyType = :currency AND w.walletStatus = 'ACTIVE'")
    List<Wallet> findActiveWalletsByUserAndCurrency(@Param("user") User user, @Param("currency") Wallet.CurrencyType currency);

    @Query("SELECT SUM(w.balance) FROM Wallet w WHERE w.user = :user AND w.currencyType = :currency")
    BigDecimal getTotalBalanceByUserAndCurrency(@Param("user") User user, @Param("currency") Wallet.CurrencyType currency);

    @Query("SELECT w FROM Wallet w WHERE w.backupCreated = false AND w.createdDate < :date")
    List<Wallet> findWalletsWithoutBackup(@Param("date") LocalDateTime date);

    @Query("SELECT COUNT(w) FROM Wallet w WHERE w.user = :user")
    long countWalletsByUser(@Param("user") User user);

    @Query("SELECT w FROM Wallet w WHERE w.keyRotationDate < :date OR w.keyRotationDate IS NULL")
    List<Wallet> findWalletsNeedingKeyRotation(@Param("date") LocalDateTime date);
}