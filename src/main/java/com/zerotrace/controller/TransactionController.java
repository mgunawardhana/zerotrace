package com.zerotrace.controller;

import com.zerotrace.dto.request.TransactionRequest;
import com.zerotrace.dto.response.TransactionResponse;
import com.zerotrace.entity.Transaction;
import com.zerotrace.security.CustomUserDetails;
import com.zerotrace.service.AuditService;
import com.zerotrace.service.TransactionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/transactions")
@PreAuthorize("hasRole('USER')")
@Tag(name = "Transaction Management", description = "Cryptocurrency transaction endpoints")
public class TransactionController {

    private static final Logger logger = LoggerFactory.getLogger(TransactionController.class);

    @Autowired
    private TransactionService transactionService;

    @Autowired
    private AuditService auditService;

    @PostMapping
    @Operation(summary = "Create a new transaction")
    public ResponseEntity<?> createTransaction(@Valid @RequestBody TransactionRequest request,
                                               @AuthenticationPrincipal CustomUserDetails userDetails,
                                               HttpServletRequest httpRequest) {
        try {
            // Create transaction
            Transaction transaction = transactionService.createTransaction(userDetails.getId(), request);

            // Audit transaction creation
            auditService.logTransactionCreation(userDetails.getId(), transaction.getId(),
                    transaction.getAmount(), httpRequest);

            logger.info("Transaction created successfully: {}", transaction.getId());
            return ResponseEntity.status(HttpStatus.CREATED).body(new TransactionResponse(transaction));

        } catch (Exception e) {
            logger.error("Failed to create transaction for user: {}", userDetails.getId(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to create transaction");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @GetMapping("/wallet/{walletId}")
    @Operation(summary = "Get transactions for a specific wallet")
    public ResponseEntity<?> getWalletTransactions(@PathVariable Long walletId,
                                                   @AuthenticationPrincipal CustomUserDetails userDetails,
                                                   @RequestParam(defaultValue = "0") int page,
                                                   @RequestParam(defaultValue = "20") int size,
                                                   @RequestParam(defaultValue = "createdDate,DESC") String sort,
                                                   @RequestParam(required = false) Transaction.TransactionStatus status,
                                                   @RequestParam(required = false) Transaction.TransactionType type,
                                                   @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
                                                   @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {
        try {
            // Parse sort parameters
            String[] sortParams = sort.split(",");
            Sort.Direction direction = sortParams.length > 1 &&
                    sortParams[1].equalsIgnoreCase("ASC") ? Sort.Direction.ASC : Sort.Direction.DESC;

            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));

            // Get transactions
            Page<Transaction> transactions = transactionService.getWalletTransactions(
                    userDetails.getId(), walletId, pageable, status, type, startDate, endDate);

            // Convert to response DTOs
            List<TransactionResponse> transactionResponses = transactions.getContent().stream()
                    .map(TransactionResponse::new)
                    .collect(Collectors.toList());

            Map<String, Object> response = new HashMap<>();
            response.put("transactions", transactionResponses);
            response.put("currentPage", transactions.getNumber());
            response.put("totalItems", transactions.getTotalElements());
            response.put("totalPages", transactions.getTotalPages());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to get transactions for wallet: {}", walletId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to retrieve transactions");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @GetMapping("/{transactionId}")
    @Operation(summary = "Get specific transaction details")
    public ResponseEntity<?> getTransaction(@PathVariable Long transactionId,
                                            @AuthenticationPrincipal CustomUserDetails userDetails) {
        try {
            Transaction transaction = transactionService.getTransactionByIdAndUser(
                    transactionId, userDetails.getId());

            return ResponseEntity.ok(new TransactionResponse(transaction));

        } catch (Exception e) {
            logger.error("Failed to get transaction: {}", transactionId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Transaction not found or access denied");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    @GetMapping("/hash/{transactionHash}")
    @Operation(summary = "Get transaction by hash")
    public ResponseEntity<?> getTransactionByHash(@PathVariable String transactionHash,
                                                  @AuthenticationPrincipal CustomUserDetails userDetails) {
        try {
            Transaction transaction = transactionService.getTransactionByHashAndUser(
                    transactionHash, userDetails.getId());

            return ResponseEntity.ok(new TransactionResponse(transaction));

        } catch (Exception e) {
            logger.error("Failed to get transaction by hash: {}", transactionHash, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Transaction not found");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    @PostMapping("/{transactionId}/cancel")
    @Operation(summary = "Cancel pending transaction")
    public ResponseEntity<?> cancelTransaction(@PathVariable Long transactionId,
                                               @AuthenticationPrincipal CustomUserDetails userDetails,
                                               HttpServletRequest httpRequest) {
        try {
            Transaction transaction = transactionService.cancelTransaction(
                    transactionId, userDetails.getId());

            // Audit transaction cancellation
            auditService.logTransactionCancellation(userDetails.getId(), transactionId, httpRequest);

            return ResponseEntity.ok(new TransactionResponse(transaction));

        } catch (Exception e) {
            logger.error("Failed to cancel transaction: {}", transactionId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to cancel transaction");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/{transactionId}/retry")
    @Operation(summary = "Retry failed transaction")
    public ResponseEntity<?> retryTransaction(@PathVariable Long transactionId,
                                              @AuthenticationPrincipal CustomUserDetails userDetails,
                                              HttpServletRequest httpRequest) {
        try {
            Transaction transaction = transactionService.retryTransaction(
                    transactionId, userDetails.getId());

            // Audit transaction retry
            auditService.logTransactionRetry(userDetails.getId(), transactionId, httpRequest);

            return ResponseEntity.ok(new TransactionResponse(transaction));

        } catch (Exception e) {
            logger.error("Failed to retry transaction: {}", transactionId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to retry transaction");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/{transactionId}/accelerate")
    @Operation(summary = "Accelerate transaction with higher fee")
    public ResponseEntity<?> accelerateTransaction(@PathVariable Long transactionId,
                                                   @AuthenticationPrincipal CustomUserDetails userDetails,
                                                   @RequestBody Map<String, Object> request,
                                                   HttpServletRequest httpRequest) {
        try {
            Double newGasPrice = Double.valueOf(request.get("newGasPrice").toString());

            Transaction transaction = transactionService.accelerateTransaction(
                    transactionId, userDetails.getId(), newGasPrice);

            // Audit transaction acceleration
            auditService.logTransactionAcceleration(userDetails.getId(), transactionId, httpRequest);

            return ResponseEntity.ok(new TransactionResponse(transaction));

        } catch (Exception e) {
            logger.error("Failed to accelerate transaction: {}", transactionId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to accelerate transaction");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @GetMapping("/estimate-fee")
    @Operation(summary = "Estimate transaction fee")
    public ResponseEntity<?> estimateTransactionFee(@RequestParam Long walletId,
                                                    @RequestParam String toAddress,
                                                    @RequestParam String amount,
                                                    @RequestParam(required = false) Integer priority,
                                                    @AuthenticationPrincipal CustomUserDetails userDetails) {
        try {
            Map<String, Object> feeEstimate = transactionService.estimateTransactionFee(
                    userDetails.getId(), walletId, toAddress, amount, priority);

            return ResponseEntity.ok(feeEstimate);

        } catch (Exception e) {
            logger.error("Failed to estimate transaction fee", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to estimate fee");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @GetMapping("/statistics")
    @Operation(summary = "Get transaction statistics")
    public ResponseEntity<?> getTransactionStatistics(@AuthenticationPrincipal CustomUserDetails userDetails,
                                                      @RequestParam(required = false) Long walletId,
                                                      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
                                                      @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {
        try {
            Map<String, Object> statistics = transactionService.getTransactionStatistics(
                    userDetails.getId(), walletId, startDate, endDate);

            return ResponseEntity.ok(statistics);

        } catch (Exception e) {
            logger.error("Failed to get transaction statistics", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to retrieve statistics");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @GetMapping("/export")
    @Operation(summary = "Export transaction history")
    public ResponseEntity<?> exportTransactions(@AuthenticationPrincipal CustomUserDetails userDetails,
                                                @RequestParam(required = false) Long walletId,
                                                @RequestParam String format,
                                                @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
                                                @RequestParam(required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {
        try {
            Map<String, Object> exportData = transactionService.exportTransactions(
                    userDetails.getId(), walletId, format, startDate, endDate);

            return ResponseEntity.ok(exportData);

        } catch (Exception e) {
            logger.error("Failed to export transactions", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to export transactions");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/validate-address")
    @Operation(summary = "Validate cryptocurrency address")
    public ResponseEntity<?> validateAddress(@RequestBody Map<String, String> request,
                                             @AuthenticationPrincipal CustomUserDetails userDetails) {
        try {
            String address = request.get("address");
            String currencyType = request.get("currencyType");

            boolean isValid = transactionService.validateAddress(address, currencyType);

            Map<String, Object> response = new HashMap<>();
            response.put("valid", isValid);
            response.put("address", address);
            response.put("currencyType", currencyType);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to validate address", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to validate address");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }
}