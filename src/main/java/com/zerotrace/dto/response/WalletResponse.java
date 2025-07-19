package com.zerotrace.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.zerotrace.entity.Wallet;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class WalletResponse {

    private Long id;
    private String walletAddress;
    private Wallet.CurrencyType currencyType;
    private String walletName;
    private BigDecimal balance;
    private BigDecimal pendingBalance;
    private Wallet.WalletStatus status;
    private Boolean backupCreated;
    private Boolean multiSignatureEnabled;
    private Integer requiredSignatures;
    private BigDecimal dailyLimit;
    private BigDecimal dailySpent;
    private Integer securityLevel;
    private Boolean coldStorage;
    private LocalDateTime createdDate;
    private LocalDateTime lastTransactionDate;
    private LocalDateTime lastSyncDate;

    // Constructors
    public WalletResponse() {}

    public WalletResponse(Wallet wallet) {
        this.id = wallet.getId();
        this.walletAddress = wallet.getWalletAddress();
        this.currencyType = wallet.getCurrencyType();
        this.walletName = wallet.getWalletName();
        this.balance = wallet.getBalance();
        this.pendingBalance = wallet.getPendingBalance();
        this.status = wallet.getWalletStatus();
        this.backupCreated = wallet.getBackupCreated();
        this.multiSignatureEnabled = wallet.getMultiSignatureEnabled();
        this.requiredSignatures = wallet.getRequiredSignatures();
        this.dailyLimit = wallet.getDailyLimit();
        this.dailySpent = wallet.getDailySpent();
        this.securityLevel = wallet.getSecurityLevel();
        this.coldStorage = wallet.getColdStorage();
        this.createdDate = wallet.getCreatedDate();
        this.lastTransactionDate = wallet.getLastTransactionDate();
        this.lastSyncDate = wallet.getLastSyncDate();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getWalletAddress() { return walletAddress; }
    public void setWalletAddress(String walletAddress) { this.walletAddress = walletAddress; }

    public Wallet.CurrencyType getCurrencyType() { return currencyType; }
    public void setCurrencyType(Wallet.CurrencyType currencyType) { this.currencyType = currencyType; }

    public String getWalletName() { return walletName; }
    public void setWalletName(String walletName) { this.walletName = walletName; }

    public BigDecimal getBalance() { return balance; }
    public void setBalance(BigDecimal balance) { this.balance = balance; }

    public BigDecimal getPendingBalance() { return pendingBalance; }
    public void setPendingBalance(BigDecimal pendingBalance) { this.pendingBalance = pendingBalance; }

    public Wallet.WalletStatus getStatus() { return status; }
    public void setStatus(Wallet.WalletStatus status) { this.status = status; }

    public Boolean getBackupCreated() { return backupCreated; }
    public void setBackupCreated(Boolean backupCreated) { this.backupCreated = backupCreated; }

    public Boolean getMultiSignatureEnabled() { return multiSignatureEnabled; }
    public void setMultiSignatureEnabled(Boolean multiSignatureEnabled) { this.multiSignatureEnabled = multiSignatureEnabled; }

    public Integer getRequiredSignatures() { return requiredSignatures; }
    public void setRequiredSignatures(Integer requiredSignatures) { this.requiredSignatures = requiredSignatures; }

    public BigDecimal getDailyLimit() { return dailyLimit; }
    public void setDailyLimit(BigDecimal dailyLimit) { this.dailyLimit = dailyLimit; }

    public BigDecimal getDailySpent() { return dailySpent; }
    public void setDailySpent(BigDecimal dailySpent) { this.dailySpent = dailySpent; }

    public Integer getSecurityLevel() { return securityLevel; }
    public void setSecurityLevel(Integer securityLevel) { this.securityLevel = securityLevel; }

    public Boolean getColdStorage() { return coldStorage; }
    public void setColdStorage(Boolean coldStorage) { this.coldStorage = coldStorage; }

    public LocalDateTime getCreatedDate() { return createdDate; }
    public void setCreatedDate(LocalDateTime createdDate) { this.createdDate = createdDate; }

    public LocalDateTime getLastTransactionDate() { return lastTransactionDate; }
    public void setLastTransactionDate(LocalDateTime lastTransactionDate) { this.lastTransactionDate = lastTransactionDate; }

    public LocalDateTime getLastSyncDate() { return lastSyncDate; }
    public void setLastSyncDate(LocalDateTime lastSyncDate) { this.lastSyncDate = lastSyncDate; }
}