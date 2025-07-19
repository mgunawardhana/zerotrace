package com.zerotrace.repository;

import com.zerotrace.entity.Transaction;
import com.zerotrace.entity.Wallet;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

@Repository
public interface TransactionRepository extends JpaRepository<Transaction, Long> {

    Optional<Transaction> findByTransactionHash(String transactionHash);

    Page<Transaction> findByWallet(Wallet wallet, Pageable pageable);

    List<Transaction> findByWalletAndStatus(Wallet wallet, Transaction.TransactionStatus status);

    @Query("SELECT t FROM Transaction t WHERE t.wallet = :wallet AND t.createdDate BETWEEN :start AND :end")
    List<Transaction> findByWalletAndDateRange(@Param("wallet") Wallet wallet,
                                               @Param("start") LocalDateTime start,
                                               @Param("end") LocalDateTime end);

    @Query("SELECT SUM(t.amount) FROM Transaction t WHERE t.wallet = :wallet AND t.transactionType = :type AND t.status = 'CONFIRMED'")
    BigDecimal getTotalAmountByWalletAndType(@Param("wallet") Wallet wallet,
                                             @Param("type") Transaction.TransactionType type);

    @Query("SELECT t FROM Transaction t WHERE t.status = 'PENDING' AND t.createdDate < :timeout")
    List<Transaction> findExpiredPendingTransactions(@Param("timeout") LocalDateTime timeout);

    @Query("SELECT t FROM Transaction t WHERE t.status = 'BROADCASTED' AND t.confirmations < :required")
    List<Transaction> findUnconfirmedTransactions(@Param("required") Integer required);

    @Query("SELECT COUNT(t) FROM Transaction t WHERE t.wallet.user.id = :userId AND t.createdDate > :since")
    long countRecentTransactionsByUser(@Param("userId") Long userId, @Param("since") LocalDateTime since);

    @Query("SELECT t FROM Transaction t WHERE t.wallet = :wallet ORDER BY t.createdDate DESC")
    List<Transaction> findRecentTransactions(@Param("wallet") Wallet wallet, Pageable pageable);
}