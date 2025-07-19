package com.zerotrace.dto.request;

import jakarta.validation.constraints.*;

import java.math.BigDecimal;

public class TransactionRequest {

    @NotNull(message = "Wallet ID is required")
    private Long walletId;

    @NotBlank(message = "To address is required")
    @Pattern(regexp = "^0x[a-fA-F0-9]{40}$|^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$",
            message = "Invalid wallet address format")
    private String toAddress;

    @NotNull(message = "Amount is required")
    @DecimalMin(value = "0.0", inclusive = false, message = "Amount must be greater than 0")
    @Digits(integer = 20, fraction = 18, message = "Invalid amount format")
    private BigDecimal amount;

    @DecimalMin(value = "0.0", message = "Gas price cannot be negative")
    private BigDecimal gasPrice;

    @Min(value = 21000, message = "Gas limit too low")
    @Max(value = 10000000, message = "Gas limit too high")
    private Long gasLimit;

    @Size(max = 500, message = "Memo cannot exceed 500 characters")
    private String memo;

    private Integer priority;
    private Boolean useMaxFee = false;
    private String twoFactorCode;

    // Getters and Setters
    public Long getWalletId() { return walletId; }
    public void setWalletId(Long walletId) { this.walletId = walletId; }

    public String getToAddress() { return toAddress; }
    public void setToAddress(String toAddress) { this.toAddress = toAddress; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public BigDecimal getGasPrice() { return gasPrice; }
    public void setGasPrice(BigDecimal gasPrice) { this.gasPrice = gasPrice; }

    public Long getGasLimit() { return gasLimit; }
    public void setGasLimit(Long gasLimit) { this.gasLimit = gasLimit; }

    public String getMemo() { return memo; }
    public void setMemo(String memo) { this.memo = memo; }

    public Integer getPriority() { return priority; }
    public void setPriority(Integer priority) { this.priority = priority; }

    public Boolean getUseMaxFee() { return useMaxFee; }
    public void setUseMaxFee(Boolean useMaxFee) { this.useMaxFee = useMaxFee; }

    public String getTwoFactorCode() { return twoFactorCode; }
    public void setTwoFactorCode(String twoFactorCode) { this.twoFactorCode = twoFactorCode; }
}