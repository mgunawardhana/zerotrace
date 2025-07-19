package com.zerotrace.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.zerotrace.entity.Transaction;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class TransactionResponse {

    private Long id;
    private String transactionHash;
    private Transaction.TransactionType type;
    private String fromAddress;
    private String toAddress;
    private BigDecimal amount;
    private BigDecimal fee;
    private Transaction.TransactionStatus status;
    private Integer confirmations;
    private Long blockNumber;
    private String blockHash;
    private String memo;
    private LocalDateTime createdDate;
    private LocalDateTime confirmedDate;
    private String errorMessage;

    // Constructors
    public TransactionResponse() {}

    public TransactionResponse(Transaction transaction) {
        this.id = transaction.getId();
        this.transactionHash = transaction.getTransactionHash();
        this.type = transaction.getTransactionType();
        this.fromAddress = transaction.getFromAddress();
        this.toAddress = transaction.getToAddress();
        this.amount = transaction.getAmount();
        this.fee = transaction.getFee();
        this.status = transaction.getStatus();
        this.confirmations = transaction.getConfirmations();
        this.blockNumber = transaction.getBlockNumber();
        this.blockHash = transaction.getBlockHash();
        this.memo = transaction.getMemo();
        this.createdDate = transaction.getCreatedDate();
        this.confirmedDate = transaction.getConfirmedDate();
        this.errorMessage = transaction.getErrorMessage();
    }

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getTransactionHash() { return transactionHash; }
    public void setTransactionHash(String transactionHash) { this.transactionHash = transactionHash; }

    public Transaction.TransactionType getType() { return type; }
    public void setType(Transaction.TransactionType type) { this.type = type; }

    public String getFromAddress() { return fromAddress; }
    public void setFromAddress(String fromAddress) { this.fromAddress = fromAddress; }

    public String getToAddress() { return toAddress; }
    public void setToAddress(String toAddress) { this.toAddress = toAddress; }

    public BigDecimal getAmount() { return amount; }
    public void setAmount(BigDecimal amount) { this.amount = amount; }

    public BigDecimal getFee() { return fee; }
    public void setFee(BigDecimal fee) { this.fee = fee; }

    public Transaction.TransactionStatus getStatus() { return status; }
    public void setStatus(Transaction.TransactionStatus status) { this.status = status; }

    public Integer getConfirmations() { return confirmations; }
    public void setConfirmations(Integer confirmations) { this.confirmations = confirmations; }

    public Long getBlockNumber() { return blockNumber; }
    public void setBlockNumber(Long blockNumber) { this.blockNumber = blockNumber; }

    public String getBlockHash() { return blockHash; }
    public void setBlockHash(String blockHash) { this.blockHash = blockHash; }

    public String getMemo() { return memo; }
    public void setMemo(String memo) { this.memo = memo; }

    public LocalDateTime getCreatedDate() { return createdDate; }
    public void setCreatedDate(LocalDateTime createdDate) { this.createdDate = createdDate; }

    public LocalDateTime getConfirmedDate() { return confirmedDate; }
    public void setConfirmedDate(LocalDateTime confirmedDate) { this.confirmedDate = confirmedDate; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}