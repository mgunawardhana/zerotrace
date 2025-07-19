package com.zerotrace.dto.request;

import com.zerotrace.entity.Wallet;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.math.BigDecimal;

public class CreateWalletRequest {

    @NotNull(message = "Currency type is required")
    private Wallet.CurrencyType currencyType;

    @Size(max = 100, message = "Wallet name cannot exceed 100 characters")
    @Pattern(regexp = "^[a-zA-Z0-9\\s-_]+$", message = "Wallet name can only contain letters, numbers, spaces, hyphens, and underscores")
    private String walletName;

    private Boolean enableMultiSignature = false;
    private Integer requiredSignatures;
    private String[] authorizedSigners;
    private BigDecimal dailyLimit;
    private Boolean coldStorage = false;
    private String hardwareWalletId;

    // Getters and Setters
    public Wallet.CurrencyType getCurrencyType() { return currencyType; }
    public void setCurrencyType(Wallet.CurrencyType currencyType) { this.currencyType = currencyType; }

    public String getWalletName() { return walletName; }
    public void setWalletName(String walletName) { this.walletName = walletName; }

    public Boolean getEnableMultiSignature() { return enableMultiSignature; }
    public void setEnableMultiSignature(Boolean enableMultiSignature) { this.enableMultiSignature = enableMultiSignature; }

    public Integer getRequiredSignatures() { return requiredSignatures; }
    public void setRequiredSignatures(Integer requiredSignatures) { this.requiredSignatures = requiredSignatures; }

    public String[] getAuthorizedSigners() { return authorizedSigners; }
    public void setAuthorizedSigners(String[] authorizedSigners) { this.authorizedSigners = authorizedSigners; }

    public BigDecimal getDailyLimit() { return dailyLimit; }
    public void setDailyLimit(BigDecimal dailyLimit) { this.dailyLimit = dailyLimit; }

    public Boolean getColdStorage() { return coldStorage; }
    public void setColdStorage(Boolean coldStorage) { this.coldStorage = coldStorage; }

    public String getHardwareWalletId() { return hardwareWalletId; }
    public void setHardwareWalletId(String hardwareWalletId) { this.hardwareWalletId = hardwareWalletId; }
}