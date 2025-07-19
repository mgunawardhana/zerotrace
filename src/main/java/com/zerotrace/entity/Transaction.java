package com.zerotrace.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.*;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.jpa.domain.support.AuditingEntityListener;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "transactions", indexes = {
        @Index(name = "idx_transaction_wallet", columnList = "wallet_id"),
        @Index(name = "idx_transaction_type", columnList = "transaction_type"),
        @Index(name = "idx_transaction_status", columnList = "status"),
        @Index(name = "idx_transaction_created", columnList = "created_date"),
        @Index(name = "idx_transaction_hash", columnList = "transaction_hash")
})
@EntityListeners(AuditingEntityListener.class)
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "wallet_id", nullable = false)
    private Wallet wallet;

    @Column(name = "transaction_hash", unique = true, length = 100)
    private String transactionHash;

    @Enumerated(EnumType.STRING)
    @Column(name = "transaction_type", nullable = false)
    private TransactionType transactionType;

    @Column(name = "from_address", nullable = false, length = 100)
    @NotBlank(message = "From address is required")
    private String fromAddress;

    @Column(name = "to_address", nullable = false, length = 100)
    @NotBlank(message = "To address is required")
    private String toAddress;

    @Column(name = "amount", nullable = false, precision = 36, scale = 18)
    @DecimalMin(value = "0.0", message = "Amount must be positive")
    @NotNull(message = "Amount is required")
    private BigDecimal amount;

    @Column(name = "fee", precision = 36, scale = 18)
    @DecimalMin(value = "0.0", message = "Fee cannot be negative")
    private BigDecimal fee = BigDecimal.ZERO;

    @Column(name = "gas_price", precision = 36, scale = 18)
    private BigDecimal gasPrice;

    @Column(name = "gas_limit")
    private Long gasLimit;

    @Column(name = "gas_used")
    private Long gasUsed;

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false)
    private TransactionStatus status = TransactionStatus.PENDING;

    @Column(name = "confirmations", nullable = false)
    private Integer confirmations = 0;

    @Column(name = "block_number")
    private Long blockNumber;

    @Column(name = "block_hash", length = 100)
    private String blockHash;

    @Column(name = "nonce")
    private Long nonce;

    @Column(name = "data", columnDefinition = "TEXT")
    private String data;

    @Column(name = "memo", length = 500)
    private String memo;

    @Column(name = "error_message", length = 1000)
    private String errorMessage;

    @Column(name = "retry_count", nullable = false)
    private Integer retryCount = 0;

    @Column(name = "max_retries", nullable = false)
    private Integer maxRetries = 3;

    @Column(name = "priority")
    private Integer priority;

    @Column(name = "signature", length = 500)
    private String signature;

    @Column(name = "signed_transaction", columnDefinition = "TEXT")
    private String signedTransaction;

    @CreatedDate
    @Column(name = "created_date", nullable = false, updatable = false)
    private LocalDateTime createdDate;

    @Column(name = "broadcasted_date")
    private LocalDateTime broadcastedDate;

    @Column(name = "confirmed_date")
    private LocalDateTime confirmedDate;

    @Column(name = "failed_date")
    private LocalDateTime failedDate;

    @Column(name = "expires_at")
    private LocalDateTime expiresAt;

    @Column(name = "created_by_ip", length = 45)
    private String createdByIp;

    @Column(name = "device_info", length = 500)
    private String deviceInfo;

    // Constructors
    public Transaction() {
        this.status = TransactionStatus.PENDING;
        this.confirmations = 0;
        this.retryCount = 0;
        this.maxRetries = 3;
        this.fee = BigDecimal.ZERO;
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public Wallet getWallet() { return wallet; }
    public void setWallet(Wallet wallet) { this.wallet = wallet; }

    public String getTransactionHash() { return transactionHash; }
    public void setTransactionHash(String transactionHash) { this.transactionHash = transactionHash; }

    public TransactionType getTransactionType() { return transactionType; }
    public void setTransactionType(TransactionType transactionType) { this.transactionType = transactionType; }

    public String getFromAddress() { return fromAddress; }
    public void setFromAddress(String fromAddress) { this.fromAddress = fromAddress; }

    public String getToAddress() { return toAddress; }
    public void setToAddress(String toAddress) { this.toAddress = toAddress; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public BigDecimal getFee() { return fee; }
    public void setFee(BigDecimal fee) { this.fee = fee; }

    public BigDecimal getGasPrice() { return gasPrice; }
    public void setGasPrice(BigDecimal gasPrice) { this.gasPrice = gasPrice; }

    public Long getGasLimit() { return gasLimit; }
    public void setGasLimit(Long gasLimit) { this.gasLimit = gasLimit; }

    public Long getGasUsed() { return gasUsed; }
    public void setGasUsed(Long gasUsed) { this.gasUsed = gasUsed; }

    public TransactionStatus getStatus() { return status; }
    public void setStatus(TransactionStatus status) { this.status = status; }

    public Integer getConfirmations() { return confirmations; }
    public void setConfirmations(Integer confirmations) { this.confirmations = confirmations; }

    public Long getBlockNumber() { return blockNumber; }
    public void setBlockNumber(Long blockNumber) { this.blockNumber = blockNumber; }

    public String getBlockHash() { return blockHash; }
    public void setBlockHash(String blockHash) { this.blockHash = blockHash; }

    public Long getNonce() { return nonce; }
    public void setNonce(Long nonce) { this.nonce = nonce; }

    public String getData() { return data; }
    public void setData(String data) { this.data = data; }

    public String getMemo() { return memo; }
    public void setMemo(String memo) { this.memo = memo; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }

    public Integer getRetryCount() { return retryCount; }
    public void setRetryCount(Integer retryCount) { this.retryCount = retryCount; }

    public Integer getMaxRetries() { return maxRetries; }
    public void setMaxRetries(Integer maxRetries) { this.maxRetries = maxRetries; }

    public Integer getPriority() { return priority; }
    public void setPriority(Integer priority) { this.priority = priority; }

    public String getSignature() { return signature; }
    public void setSignature(String signature) { this.signature = signature; }

    public String getSignedTransaction() { return signedTransaction; }
    public void setSignedTransaction(String signedTransaction) { this.signedTransaction = signedTransaction; }

    public LocalDateTime getCreatedDate() { return createdDate; }
    public void setCreatedDate(LocalDateTime createdDate) { this.createdDate = createdDate; }

    public LocalDateTime getBroadcastedDate() { return broadcastedDate; }
    public void setBroadcastedDate(LocalDateTime broadcastedDate) { this.broadcastedDate = broadcastedDate; }

    public LocalDateTime getConfirmedDate() { return confirmedDate; }
    public void setConfirmedDate(LocalDateTime confirmedDate) { this.confirmedDate = confirmedDate; }

    public LocalDateTime getFailedDate() { return failedDate; }
    public void setFailedDate(LocalDateTime failedDate) { this.failedDate = failedDate; }

    public LocalDateTime getExpiresAt() { return expiresAt; }
    public void setExpiresAt(LocalDateTime expiresAt) { this.expiresAt = expiresAt; }

    public String getCreatedByIp() { return createdByIp; }
    public void setCreatedByIp(String createdByIp) { this.createdByIp = createdByIp; }

    public String getDeviceInfo() { return deviceInfo; }
    public void setDeviceInfo(String deviceInfo) { this.deviceInfo = deviceInfo; }

    // Enums
    public enum TransactionType {
        SEND, RECEIVE, INTERNAL, CONTRACT_INTERACTION, TOKEN_TRANSFER, SWAP, STAKE, UNSTAKE
    }

    public enum TransactionStatus {
        PENDING, BROADCASTED, CONFIRMING, CONFIRMED, FAILED, CANCELLED, EXPIRED
    }
}