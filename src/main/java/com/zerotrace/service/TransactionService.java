package com.zerotrace.service;

import com.zerotrace.dto.request.TransactionRequest;
import com.zerotrace.entity.Transaction;
import com.zerotrace.entity.User;
import com.zerotrace.entity.Wallet;
import com.zerotrace.repository.TransactionRepository;
import com.zerotrace.repository.UserRepository;
import com.zerotrace.repository.WalletRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.domain.Specification;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.persistence.criteria.Predicate;
import java.math.BigDecimal;
import java.security.MessageDigest;
import java.time.LocalDateTime;
import java.util.*;
import java.util.regex.Pattern;

@Service
@Transactional
public class TransactionService {

    private static final Logger logger = LoggerFactory.getLogger(TransactionService.class);

    // Address validation patterns
    private static final Pattern BTC_ADDRESS_PATTERN = Pattern.compile("^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,62}$");
    private static final Pattern ETH_ADDRESS_PATTERN = Pattern.compile("^0x[a-fA-F0-9]{40}$");
    private static final Pattern ADA_ADDRESS_PATTERN = Pattern.compile("^addr1[a-z0-9]{58}$");
    private static final Pattern SOL_ADDRESS_PATTERN = Pattern.compile("^[1-9A-HJ-NP-Za-km-z]{32,44}$");

    @Autowired
    private TransactionRepository transactionRepository;

    @Autowired
    private WalletRepository walletRepository;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private EncryptionService encryptionService;

    @Autowired
    private KeyManagementService keyManagementService;

    public Transaction createTransaction(Long userId, TransactionRequest request) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Wallet wallet = walletRepository.findByIdAndUser(request.getWalletId(), user)
                .orElseThrow(() -> new RuntimeException("Wallet not found"));

        // Verify wallet status
        if (wallet.getWalletStatus() != Wallet.WalletStatus.ACTIVE) {
            throw new RuntimeException("Wallet is not active");
        }

        // Verify 2FA if enabled
        if (user.getTwoFactorEnabled() && request.getTwoFactorCode() != null) {
            // TODO: Verify 2FA code
        }

        // Validate recipient address
        if (!validateAddress(request.getToAddress(), wallet.getCurrencyType().toString())) {
            throw new RuntimeException("Invalid recipient address");
        }

        // Check balance
        BigDecimal totalAmount = request.getAmount();
        if (request.getGasPrice() != null && request.getGasLimit() != null) {
            BigDecimal gasFee = request.getGasPrice().multiply(new BigDecimal(request.getGasLimit()));
            totalAmount = totalAmount.add(gasFee);
        }

        if (wallet.getBalance().compareTo(totalAmount) < 0) {
            throw new RuntimeException("Insufficient balance");
        }

        // Check daily limit
        if (wallet.getDailyLimit() != null) {
            checkDailyLimit(wallet, request.getAmount());
        }

        // Create transaction
        Transaction transaction = new Transaction();
        transaction.setWallet(wallet);
        transaction.setTransactionType(Transaction.TransactionType.SEND);
        transaction.setFromAddress(wallet.getWalletAddress());
        transaction.setToAddress(request.getToAddress());
        transaction.setAmount(request.getAmount());
        transaction.setGasPrice(request.getGasPrice());
        transaction.setGasLimit(request.getGasLimit());
        transaction.setMemo(request.getMemo());
        transaction.setPriority(request.getPriority());
        transaction.setCreatedByIp(getClientIp());

        // Generate transaction hash
        String transactionHash = generateTransactionHash(transaction);
        transaction.setTransactionHash(transactionHash);

        // Update wallet balances
        wallet.setBalance(wallet.getBalance().subtract(totalAmount));
        wallet.setPendingBalance(wallet.getPendingBalance().add(totalAmount));
        wallet.setLastTransactionDate(LocalDateTime.now());
        walletRepository.save(wallet);

        // Save transaction
        transaction = transactionRepository.save(transaction);

        // Broadcast transaction asynchronously
        broadcastTransaction(transaction);

        logger.info("Transaction created: {} from wallet: {}", transaction.getId(), wallet.getId());
        return transaction;
    }

    public Page<Transaction> getWalletTransactions(Long userId, Long walletId, Pageable pageable,
                                                   Transaction.TransactionStatus status,
                                                   Transaction.TransactionType type,
                                                   LocalDateTime startDate,
                                                   LocalDateTime endDate) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Wallet wallet = walletRepository.findByIdAndUser(walletId, user)
                .orElseThrow(() -> new RuntimeException("Wallet not found"));

        Specification<Transaction> spec = Specification.where(
                (root, query, cb) -> cb.equal(root.get("wallet"), wallet)
        );

        if (status != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("status"), status));
        }

        if (type != null) {
            spec = spec.and((root, query, cb) -> cb.equal(root.get("transactionType"), type));
        }

        if (startDate != null && endDate != null) {
            spec = spec.and((root, query, cb) -> cb.between(root.get("createdDate"), startDate, endDate));
        }

        return transactionRepository.findAll(spec, pageable);
    }

    public Transaction getTransactionByIdAndUser(Long transactionId, Long userId) {
        Transaction transaction = transactionRepository.findById(transactionId)
                .orElseThrow(() -> new RuntimeException("Transaction not found"));

        if (!transaction.getWallet().getUser().getId().equals(userId)) {
            throw new RuntimeException("Access denied");
        }

        return transaction;
    }

    public Transaction getTransactionByHashAndUser(String transactionHash, Long userId) {
        Transaction transaction = transactionRepository.findByTransactionHash(transactionHash)
                .orElseThrow(() -> new RuntimeException("Transaction not found"));

        if (!transaction.getWallet().getUser().getId().equals(userId)) {
            throw new RuntimeException("Access denied");
        }

        return transaction;
    }

    public Transaction cancelTransaction(Long transactionId, Long userId) {
        Transaction transaction = getTransactionByIdAndUser(transactionId, userId);

        if (transaction.getStatus() != Transaction.TransactionStatus.PENDING) {
            throw new RuntimeException("Only pending transactions can be cancelled");
        }

        // Update transaction status
        transaction.setStatus(Transaction.TransactionStatus.CANCELLED);
        transaction.setFailedDate(LocalDateTime.now());
        transaction.setErrorMessage("Cancelled by user");

        // Restore wallet balance
        Wallet wallet = transaction.getWallet();
        BigDecimal totalAmount = transaction.getAmount();
        if (transaction.getFee() != null) {
            totalAmount = totalAmount.add(transaction.getFee());
        }

        wallet.setBalance(wallet.getBalance().add(totalAmount));
        wallet.setPendingBalance(wallet.getPendingBalance().subtract(totalAmount));
        walletRepository.save(wallet);

        return transactionRepository.save(transaction);
    }

    public Transaction retryTransaction(Long transactionId, Long userId) {
        Transaction transaction = getTransactionByIdAndUser(transactionId, userId);

        if (transaction.getStatus() != Transaction.TransactionStatus.FAILED) {
            throw new RuntimeException("Only failed transactions can be retried");
        }

        if (transaction.getRetryCount() >= transaction.getMaxRetries()) {
            throw new RuntimeException("Maximum retry attempts exceeded");
        }

        // Check wallet balance again
        Wallet wallet = transaction.getWallet();
        BigDecimal totalAmount = transaction.getAmount();
        if (transaction.getFee() != null) {
            totalAmount = totalAmount.add(transaction.getFee());
        }

        if (wallet.getBalance().compareTo(totalAmount) < 0) {
            throw new RuntimeException("Insufficient balance");
        }

        // Update transaction
        transaction.setStatus(Transaction.TransactionStatus.PENDING);
        transaction.setRetryCount(transaction.getRetryCount() + 1);
        transaction.setErrorMessage(null);
        transaction.setFailedDate(null);

        // Update wallet balances
        wallet.setBalance(wallet.getBalance().subtract(totalAmount));
        wallet.setPendingBalance(wallet.getPendingBalance().add(totalAmount));
        walletRepository.save(wallet);

        transaction = transactionRepository.save(transaction);

        // Retry broadcast
        broadcastTransaction(transaction);

        return transaction;
    }

    public Transaction accelerateTransaction(Long transactionId, Long userId, Double newGasPrice) {
        Transaction transaction = getTransactionByIdAndUser(transactionId, userId);

        if (transaction.getStatus() != Transaction.TransactionStatus.PENDING &&
                transaction.getStatus() != Transaction.TransactionStatus.BROADCASTED) {
            throw new RuntimeException("Transaction cannot be accelerated");
        }

        // Calculate additional fee needed
        BigDecimal oldGasPrice = transaction.getGasPrice() != null ?
                transaction.getGasPrice() : BigDecimal.ZERO;
        BigDecimal additionalFee = new BigDecimal(newGasPrice)
                .subtract(oldGasPrice)
                .multiply(new BigDecimal(transaction.getGasLimit()));

        // Check wallet balance for additional fee
        Wallet wallet = transaction.getWallet();
        if (wallet.getBalance().compareTo(additionalFee) < 0) {
            throw new RuntimeException("Insufficient balance for acceleration fee");
        }

        // Update transaction
        transaction.setGasPrice(new BigDecimal(newGasPrice));
        transaction.setPriority(5); // High priority

        // Update wallet balance
        wallet.setBalance(wallet.getBalance().subtract(additionalFee));
        wallet.setPendingBalance(wallet.getPendingBalance().add(additionalFee));
        walletRepository.save(wallet);

        transaction = transactionRepository.save(transaction);

        // Re-broadcast with higher fee
        broadcastTransaction(transaction);

        return transaction;
    }

    public Map<String, Object> estimateTransactionFee(Long userId, Long walletId,
                                                      String toAddress, String amount, Integer priority) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Wallet wallet = walletRepository.findByIdAndUser(walletId, user)
                .orElseThrow(() -> new RuntimeException("Wallet not found"));

        // Validate address
        if (!validateAddress(toAddress, wallet.getCurrencyType().toString())) {
            throw new RuntimeException("Invalid recipient address");
        }

        Map<String, Object> feeEstimate = new HashMap<>();

        // Estimate based on currency type and network conditions
        BigDecimal baseFee = estimateBaseFee(wallet.getCurrencyType());
        BigDecimal priorityMultiplier = getPriorityMultiplier(priority);
        BigDecimal estimatedFee = baseFee.multiply(priorityMultiplier);

        feeEstimate.put("estimatedFee", estimatedFee);
        feeEstimate.put("currency", wallet.getCurrencyType());
        feeEstimate.put("priority", priority != null ? priority : 2);
        feeEstimate.put("estimatedTime", getEstimatedConfirmationTime(priority));
        feeEstimate.put("gasPrice", estimatedFee.divide(new BigDecimal("21000"), 8, BigDecimal.ROUND_HALF_UP));
        feeEstimate.put("gasLimit", 21000L);

        return feeEstimate;
    }

    public Map<String, Object> getTransactionStatistics(Long userId, Long walletId,
                                                        LocalDateTime startDate, LocalDateTime endDate) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        Map<String, Object> statistics = new HashMap<>();

        if (walletId != null) {
            Wallet wallet = walletRepository.findByIdAndUser(walletId, user)
                    .orElseThrow(() -> new RuntimeException("Wallet not found"));

            // Get statistics for specific wallet
            statistics.put("totalSent", getTotalAmountByTypeAndWallet(wallet, Transaction.TransactionType.SEND));
            statistics.put("totalReceived", getTotalAmountByTypeAndWallet(wallet, Transaction.TransactionType.RECEIVE));
            statistics.put("transactionCount", getTransactionCount(wallet, startDate, endDate));
            statistics.put("pendingTransactions", getPendingTransactionCount(wallet));
            statistics.put("averageTransactionAmount", getAverageTransactionAmount(wallet, startDate, endDate));
            statistics.put("largestTransaction", getLargestTransaction(wallet, startDate, endDate));
        } else {
            // Get statistics for all user wallets
            List<Wallet> userWallets = walletRepository.findByUser(user);
            BigDecimal totalSent = BigDecimal.ZERO;
            BigDecimal totalReceived = BigDecimal.ZERO;
            long totalTransactions = 0;
            long pendingTransactions = 0;

            for (Wallet wallet : userWallets) {
                totalSent = totalSent.add(getTotalAmountByTypeAndWallet(wallet, Transaction.TransactionType.SEND));
                totalReceived = totalReceived.add(getTotalAmountByTypeAndWallet(wallet, Transaction.TransactionType.RECEIVE));
                totalTransactions += getTransactionCount(wallet, startDate, endDate);
                pendingTransactions += getPendingTransactionCount(wallet);
            }

            statistics.put("totalSent", totalSent);
            statistics.put("totalReceived", totalReceived);
            statistics.put("transactionCount", totalTransactions);
            statistics.put("pendingTransactions", pendingTransactions);
            statistics.put("walletCount", userWallets.size());
        }

        statistics.put("startDate", startDate);
        statistics.put("endDate", endDate);

        return statistics;
    }

    public Map<String, Object> exportTransactions(Long userId, Long walletId, String format,
                                                  LocalDateTime startDate, LocalDateTime endDate) {
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new RuntimeException("User not found"));

        List<Transaction> transactions;

        if (walletId != null) {
            Wallet wallet = walletRepository.findByIdAndUser(walletId, user)
                    .orElseThrow(() -> new RuntimeException("Wallet not found"));
            transactions = transactionRepository.findByWalletAndDateRange(wallet, startDate, endDate);
        } else {
            // Get all transactions for user
            List<Wallet> userWallets = walletRepository.findByUser(user);
            transactions = new ArrayList<>();
            for (Wallet wallet : userWallets) {
                transactions.addAll(transactionRepository.findByWalletAndDateRange(wallet, startDate, endDate));
            }
        }

        Map<String, Object> exportData = new HashMap<>();
        exportData.put("format", format);
        exportData.put("transactionCount", transactions.size());
        exportData.put("exportDate", LocalDateTime.now());

        if ("json".equalsIgnoreCase(format)) {
            exportData.put("transactions", transactions);
        } else if ("csv".equalsIgnoreCase(format)) {
            String csvData = convertTransactionsToCsv(transactions);
            exportData.put("data", csvData);
        }

        return exportData;
    }

    public boolean validateAddress(String address, String currencyType) {
        if (address == null || address.isEmpty()) {
            return false;
        }

        try {
            Wallet.CurrencyType currency = Wallet.CurrencyType.valueOf(currencyType.toUpperCase());

            switch (currency) {
                case BTC:
                    return BTC_ADDRESS_PATTERN.matcher(address).matches();
                case ETH:
                case USDT:
                case USDC:
                case BNB:
                case MATIC:
                case AVAX:
                    return ETH_ADDRESS_PATTERN.matcher(address).matches();
                case ADA:
                    return ADA_ADDRESS_PATTERN.matcher(address).matches();
                case SOL:
                    return SOL_ADDRESS_PATTERN.matcher(address).matches();
                case DOT:
                    // Polkadot addresses are complex, simplified validation
                    return address.length() >= 46 && address.length() <= 48;
                default:
                    return false;
            }
        } catch (Exception e) {
            return false;
        }
    }

    // Helper methods
    private void checkDailyLimit(Wallet wallet, BigDecimal amount) {
        // Reset daily limit if needed
        if (wallet.getDailyLimitReset() != null &&
                wallet.getDailyLimitReset().isBefore(LocalDateTime.now())) {
            wallet.setDailySpent(BigDecimal.ZERO);
            wallet.setDailyLimitReset(LocalDateTime.now().plusDays(1));
        }

        BigDecimal newDailySpent = wallet.getDailySpent().add(amount);
        if (newDailySpent.compareTo(wallet.getDailyLimit()) > 0) {
            throw new RuntimeException("Daily transaction limit exceeded");
        }

        wallet.setDailySpent(newDailySpent);
    }

    private String generateTransactionHash(Transaction transaction) {
        try {
            String data = transaction.getFromAddress() +
                    transaction.getToAddress() +
                    transaction.getAmount().toString() +
                    System.currentTimeMillis() +
                    UUID.randomUUID().toString();

            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data.getBytes("UTF-8"));

            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) hexString.append('0');
                hexString.append(hex);
            }

            return "0x" + hexString.toString();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate transaction hash", e);
        }
    }

    private void broadcastTransaction(Transaction transaction) {
        // TODO: Implement actual blockchain broadcast
        // This would connect to blockchain nodes to broadcast the transaction

        // Simulate broadcast
        transaction.setStatus(Transaction.TransactionStatus.BROADCASTED);
        transaction.setBroadcastedDate(LocalDateTime.now());
        transactionRepository.save(transaction);

        // Simulate confirmation process
        scheduleTransactionConfirmation(transaction);
    }

    private void scheduleTransactionConfirmation(Transaction transaction) {
        // TODO: Implement actual confirmation monitoring
        // This would monitor blockchain for confirmations
    }

    private BigDecimal estimateBaseFee(Wallet.CurrencyType currencyType) {
        // Simplified fee estimation - in production, get from blockchain
        switch (currencyType) {
            case BTC:
                return new BigDecimal("0.0001");
            case ETH:
                return new BigDecimal("0.001");
            case BNB:
                return new BigDecimal("0.0005");
            default:
                return new BigDecimal("0.0001");
        }
    }

    private BigDecimal getPriorityMultiplier(Integer priority) {
        if (priority == null) priority = 2;

        switch (priority) {
            case 1: return new BigDecimal("0.8");  // Low
            case 2: return new BigDecimal("1.0");  // Normal
            case 3: return new BigDecimal("1.5");  // High
            case 4: return new BigDecimal("2.0");  // Urgent
            case 5: return new BigDecimal("3.0");  // Critical
            default: return new BigDecimal("1.0");
        }
    }

    private String getEstimatedConfirmationTime(Integer priority) {
        if (priority == null) priority = 2;

        switch (priority) {
            case 1: return "30-60 minutes";
            case 2: return "10-30 minutes";
            case 3: return "5-10 minutes";
            case 4: return "2-5 minutes";
            case 5: return "Next block";
            default: return "10-30 minutes";
        }
    }

    private BigDecimal getTotalAmountByTypeAndWallet(Wallet wallet, Transaction.TransactionType type) {
        BigDecimal total = transactionRepository.getTotalAmountByWalletAndType(wallet, type);
        return total != null ? total : BigDecimal.ZERO;
    }

    private long getTransactionCount(Wallet wallet, LocalDateTime startDate, LocalDateTime endDate) {
        if (startDate != null && endDate != null) {
            return transactionRepository.findByWalletAndDateRange(wallet, startDate, endDate).size();
        }
        return transactionRepository.count((root, query, cb) -> cb.equal(root.get("wallet"), wallet));
    }

    private long getPendingTransactionCount(Wallet wallet) {
        return transactionRepository.findByWalletAndStatus(wallet, Transaction.TransactionStatus.PENDING).size();
    }

    private BigDecimal getAverageTransactionAmount(Wallet wallet, LocalDateTime startDate, LocalDateTime endDate) {
        List<Transaction> transactions = transactionRepository.findByWalletAndDateRange(wallet,
                startDate != null ? startDate : LocalDateTime.now().minusYears(1),
                endDate != null ? endDate : LocalDateTime.now());

        if (transactions.isEmpty()) {
            return BigDecimal.ZERO;
        }

        BigDecimal total = transactions.stream()
                .map(Transaction::getAmount)
                .reduce(BigDecimal.ZERO, BigDecimal::add);

        return total.divide(new BigDecimal(transactions.size()), 8, BigDecimal.ROUND_HALF_UP);
    }

    private Transaction getLargestTransaction(Wallet wallet, LocalDateTime startDate, LocalDateTime endDate) {
        List<Transaction> transactions = transactionRepository.findByWalletAndDateRange(wallet,
                startDate != null ? startDate : LocalDateTime.now().minusYears(1),
                endDate != null ? endDate : LocalDateTime.now());

        return transactions.stream()
                .max(Comparator.comparing(Transaction::getAmount))
                .orElse(null);
    }

    private String convertTransactionsToCsv(List<Transaction> transactions) {
        StringBuilder csv = new StringBuilder();
        csv.append("ID,Date,Type,From,To,Amount,Fee,Status,Hash\n");

        for (Transaction tx : transactions) {
            csv.append(tx.getId()).append(",")
                    .append(tx.getCreatedDate()).append(",")
                    .append(tx.getTransactionType()).append(",")
                    .append(tx.getFromAddress()).append(",")
                    .append(tx.getToAddress()).append(",")
                    .append(tx.getAmount()).append(",")
                    .append(tx.getFee() != null ? tx.getFee() : "0").append(",")
                    .append(tx.getStatus()).append(",")
                    .append(tx.getTransactionHash()).append("\n");
        }

        return csv.toString();
    }

    private String getClientIp() {
        // TODO: Get actual client IP from request context
        return "127.0.0.1";
    }
}