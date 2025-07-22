package com.zerotrace.controller;

import com.zerotrace.dto.request.CreateWalletRequest;
import com.zerotrace.dto.response.WalletResponse;
import com.zerotrace.entity.Wallet;
import com.zerotrace.service.AuditService;
import com.zerotrace.service.WalletService;
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
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/wallets")
@PreAuthorize("hasRole('USER')")
@Tag(name = "Wallet Management", description = "Wallet creation and management endpoints")
public class WalletController {

    private static final Logger logger = LoggerFactory.getLogger(WalletController.class);

    @Autowired
    private WalletService walletService;

    @Autowired
    private AuditService auditService;

    @PostMapping
    @Operation(summary = "Create a new wallet")
    public ResponseEntity<?> createWallet(@Valid @RequestBody CreateWalletRequest request,
                                          @AuthenticationPrincipal CustomUserDetails userDetails,
                                          HttpServletRequest httpRequest) {
        try {
            // Create wallet
            Wallet wallet = walletService.createWallet(userDetails.getId(), request);

            // Audit wallet creation
            auditService.logWalletCreation(userDetails.getId(), wallet.getId(), httpRequest);

            logger.info("Wallet created successfully for user: {}", userDetails.getId());
            return ResponseEntity.status(HttpStatus.CREATED).body(new WalletResponse(wallet));

        } catch (Exception e) {
            logger.error("Failed to create wallet for user: {}", userDetails.getId(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to create wallet");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @GetMapping
    @Operation(summary = "Get all wallets for authenticated user")
    public ResponseEntity<?> getUserWallets(@AuthenticationPrincipal CustomUserDetails userDetails,
                                            @RequestParam(defaultValue = "0") int page,
                                            @RequestParam(defaultValue = "10") int size,
                                            @RequestParam(defaultValue = "createdDate,DESC") String sort) {
        try {
            // Parse sort parameters
            String[] sortParams = sort.split(",");
            Sort.Direction direction = sortParams.length > 1 &&
                    sortParams[1].equalsIgnoreCase("ASC") ? Sort.Direction.ASC : Sort.Direction.DESC;

            Pageable pageable = PageRequest.of(page, size, Sort.by(direction, sortParams[0]));

            // Get wallets
            Page<Wallet> wallets = walletService.getUserWallets(userDetails.getId(), pageable);

            // Convert to response DTOs
            List<WalletResponse> walletResponses = wallets.getContent().stream()
                    .map(WalletResponse::new)
                    .collect(Collectors.toList());

            Map<String, Object> response = new HashMap<>();
            response.put("wallets", walletResponses);
            response.put("currentPage", wallets.getNumber());
            response.put("totalItems", wallets.getTotalElements());
            response.put("totalPages", wallets.getTotalPages());

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to get wallets for user: {}", userDetails.getId(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to retrieve wallets");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @GetMapping("/{walletId}")
    @Operation(summary = "Get specific wallet details")
    public ResponseEntity<?> getWallet(@PathVariable Long walletId,
                                       @AuthenticationPrincipal CustomUserDetails userDetails) {
        try {
            // Get wallet with ownership check
            Wallet wallet = walletService.getWalletByIdAndUser(walletId, userDetails.getId());

            return ResponseEntity.ok(new WalletResponse(wallet));

        } catch (Exception e) {
            logger.error("Failed to get wallet {} for user: {}", walletId, userDetails.getId(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Wallet not found or access denied");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(error);
        }
    }

    @PutMapping("/{walletId}")
    @Operation(summary = "Update wallet settings")
    public ResponseEntity<?> updateWallet(@PathVariable Long walletId,
                                          @RequestBody Map<String, Object> updates,
                                          @AuthenticationPrincipal CustomUserDetails userDetails,
                                          HttpServletRequest httpRequest) {
        try {
            // Update wallet
            Wallet wallet = walletService.updateWallet(walletId, userDetails.getId(), updates);

            // Audit wallet update
            auditService.logWalletUpdate(userDetails.getId(), walletId, updates, httpRequest);

            return ResponseEntity.ok(new WalletResponse(wallet));

        } catch (Exception e) {
            logger.error("Failed to update wallet {} for user: {}", walletId, userDetails.getId(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to update wallet");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/{walletId}/backup")
    @Operation(summary = "Create wallet backup")
    public ResponseEntity<?> createWalletBackup(@PathVariable Long walletId,
                                                @AuthenticationPrincipal CustomUserDetails userDetails,
                                                @RequestBody Map<String, String> request,
                                                HttpServletRequest httpRequest) {
        try {
            String password = request.get("password");

            // Create backup
            Map<String, String> backup = walletService.createWalletBackup(walletId, userDetails.getId(), password);

            // Audit backup creation
            auditService.logWalletBackup(userDetails.getId(), walletId, httpRequest);

            return ResponseEntity.ok(backup);

        } catch (Exception e) {
            logger.error("Failed to create backup for wallet {}", walletId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to create wallet backup");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/{walletId}/verify-backup")
    @Operation(summary = "Verify wallet backup")
    public ResponseEntity<?> verifyWalletBackup(@PathVariable Long walletId,
                                                @AuthenticationPrincipal CustomUserDetails userDetails,
                                                @RequestBody Map<String, String> request) {
        try {
            String backupPhrase = request.get("backupPhrase");

            boolean verified = walletService.verifyWalletBackup(walletId, userDetails.getId(), backupPhrase);

            Map<String, Object> response = new HashMap<>();
            response.put("verified", verified);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to verify backup for wallet {}", walletId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to verify wallet backup");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @GetMapping("/{walletId}/balance")
    @Operation(summary = "Get wallet balance")
    public ResponseEntity<?> getWalletBalance(@PathVariable Long walletId,
                                              @AuthenticationPrincipal CustomUserDetails userDetails,
                                              @RequestParam(defaultValue = "false") boolean refresh) {
        try {
            Map<String, Object> balance = walletService.getWalletBalance(walletId, userDetails.getId(), refresh);

            return ResponseEntity.ok(balance);

        } catch (Exception e) {
            logger.error("Failed to get balance for wallet {}", walletId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to retrieve wallet balance");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/{walletId}/lock")
    @Operation(summary = "Lock wallet")
    public ResponseEntity<?> lockWallet(@PathVariable Long walletId,
                                        @AuthenticationPrincipal CustomUserDetails userDetails,
                                        HttpServletRequest httpRequest) {
        try {
            walletService.lockWallet(walletId, userDetails.getId());

            // Audit wallet lock
            auditService.logWalletLock(userDetails.getId(), walletId, httpRequest);

            Map<String, String> response = new HashMap<>();
            response.put("message", "Wallet locked successfully");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to lock wallet {}", walletId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to lock wallet");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/{walletId}/unlock")
    @Operation(summary = "Unlock wallet")
    public ResponseEntity<?> unlockWallet(@PathVariable Long walletId,
                                          @AuthenticationPrincipal CustomUserDetails userDetails,
                                          @RequestBody Map<String, String> request,
                                          HttpServletRequest httpRequest) {
        try {
            String password = request.get("password");

            walletService.unlockWallet(walletId, userDetails.getId(), password);

            // Audit wallet unlock
            auditService.logWalletUnlock(userDetails.getId(), walletId, httpRequest);

            Map<String, String> response = new HashMap<>();
            response.put("message", "Wallet unlocked successfully");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to unlock wallet {}", walletId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to unlock wallet");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @DeleteMapping("/{walletId}")
    @Operation(summary = "Archive wallet (soft delete)")
    public ResponseEntity<?> archiveWallet(@PathVariable Long walletId,
                                           @AuthenticationPrincipal CustomUserDetails userDetails,
                                           @RequestBody Map<String, String> request,
                                           HttpServletRequest httpRequest) {
        try {
            String password = request.get("password");
            String reason = request.get("reason");

            walletService.archiveWallet(walletId, userDetails.getId(), password, reason);

            // Audit wallet archive
            auditService.logWalletArchive(userDetails.getId(), walletId, reason, httpRequest);

            Map<String, String> response = new HashMap<>();
            response.put("message", "Wallet archived successfully");

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to archive wallet {}", walletId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to archive wallet");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @GetMapping("/currencies")
    @Operation(summary = "Get supported currencies")
    public ResponseEntity<?> getSupportedCurrencies() {
        try {
            List<Map<String, String>> currencies = walletService.getSupportedCurrencies();
            return ResponseEntity.ok(currencies);

        } catch (Exception e) {
            logger.error("Failed to get supported currencies", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/{walletId}/export")
    @Operation(summary = "Export wallet data")
    public ResponseEntity<?> exportWallet(@PathVariable Long walletId,
                                          @AuthenticationPrincipal CustomUserDetails userDetails,
                                          @RequestParam String format) {
        try {
            Map<String, Object> exportData = walletService.exportWalletData(walletId, userDetails.getId(), format);

            return ResponseEntity.ok(exportData);

        } catch (Exception e) {
            logger.error("Failed to export wallet {}", walletId, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to export wallet");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }
}
