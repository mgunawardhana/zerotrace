package com.zerotrace.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "wallets", indexes = {
        @Index(name = "idx_wallet_user", columnList = "user_id"),
        @Index(name = "idx_wallet_address", columnList = "wallet_address"),
        @Index(name = "idx_wallet_currency", columnList = "currency_type"),
        @Index(name = "idx_wallet_status", columnList = "wallet_status")
})
@EntityListeners(AuditingEntityListener.class)
public class Wallet {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "wallet_address", nullable = false, unique = true, length = 100)
    @NotBlank(message = "Wallet address is required")
    private String walletAddress;

    @Enumerated(EnumType.STRING)
    @Column(name = "currency_type", nullable = false, length = 20)
    private CurrencyType currencyType;

    @Column(name = "wallet_name", length = 100)
    @Size(max = 100, message = "Wallet name cannot exceed 100 characters")
    private String walletName;

    @Column(name = "encrypted_private_key", nullable = false, length = 1000)
    private String encryptedPrivateKey;

    @Column(name = "encrypted_mnemonic", length = 1000)
    private String encryptedMnemonic;

    @Column(name = "public_key", nullable = false, length = 500)
    private String publicKey;

    @Column(name = "balance", nullable = false, precision = 36, scale = 18)
    @DecimalMin(value = "0.0", message = "Balance cannot be negative")
    private BigDecimal balance = BigDecimal.ZERO;

    @Column(name = "pending_balance", nullable = false, precision = 36, scale = 18)
    @DecimalMin(value = "0.0", message = "Pending balance cannot be negative")
    private BigDecimal pendingBalance = BigDecimal.ZERO;

    @Enumerated(EnumType.STRING)
    @Column(name = "wallet_status", nullable = false)
    private WalletStatus walletStatus = WalletStatus.ACTIVE;

    @Column(name = "derivation_path", length = 100)
    private String derivationPath;

    @Column(name = "wallet_index")
    private Integer walletIndex;

    @Column(name = "encryption_timestamp", nullable = false)
    private Long encryptionTimestamp;

    @Column(name = "key_rotation_date")
    private LocalDateTime keyRotationDate;

    @Column(name = "last_sync_date")
    private LocalDateTime lastSyncDate;

    @Column(name = "last_transaction_date")
    private LocalDateTime lastTransactionDate;

    @Column(name = "backup_created", nullable = false)
    private Boolean backupCreated = false;

    @Column(name = "backup_verified", nullable = false)
    private Boolean backupVerified = false;

    @Column(name = "multi_signature_enabled", nullable = false)
    private Boolean multiSignatureEnabled = false;

    @Column(name = "required_signatures")
    private Integer requiredSignatures;

    @Column(name = "authorized_signers", length = 2000)
    private String authorizedSigners;

    @Column(name = "daily_limit", precision = 36, scale = 18)
    private BigDecimal dailyLimit;

    @Column(name = "daily_spent", precision = 36, scale = 18)
    @DecimalMin(value = "0.0")
    private BigDecimal dailySpent = BigDecimal.ZERO;

    @Column(name = "daily_limit_reset")
    private LocalDateTime dailyLimitReset;

    @Column(name = "security_level", nullable = false)
    private Integer securityLevel = 1;

    @Column(name = "cold_storage", nullable = false)
    private Boolean coldStorage = false;

    @Column(name = "hardware_wallet_id", length = 100)
    private String hardwareWalletId;

    @CreatedDate
    @Column(name = "created_date", nullable = false, updatable = false)
    private LocalDateTime createdDate;

    @LastModifiedDate
    @Column(name = "modified_date")
    private LocalDateTime modifiedDate;

    @Column(name = "created_by_ip", length = 45)
    private String createdByIp;

    @OneToMany(mappedBy = "wallet", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<Transaction> transactions = new ArrayList<>();