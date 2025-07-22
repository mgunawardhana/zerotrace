package com.zerotrace.controller;

import com.zerotrace.dto.request.LoginRequest;
import com.zerotrace.dto.request.RegisterRequest;
import com.zerotrace.dto.response.AuthResponse;
import com.zerotrace.service.AuthService;
import com.zerotrace.service.AuditService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@Tag(name = "Authentication", description = "Authentication management endpoints")
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private AuthService authService;

    @Autowired
    private AuditService auditService;

    @PostMapping("/register")
    @Operation(summary = "Register a new user")
    public ResponseEntity<?> registerUser(@Valid @RequestBody RegisterRequest registerRequest,
                                          HttpServletRequest request) {
        try {
            // Add IP address to request
            registerRequest.setIpAddress(getClientIp(request));

            // Register user
            AuthResponse response = authService.registerUser(registerRequest);

            // Audit successful registration
            auditService.logUserRegistration(response.getUserId(), request);

            logger.info("User registered successfully: {}", registerRequest.getEmail());
            return ResponseEntity.status(HttpStatus.CREATED).body(response);

        } catch (Exception e) {
            logger.error("Registration failed for email: {}", registerRequest.getEmail(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Registration failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/login")
    @Operation(summary = "Authenticate user and receive JWT tokens")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest,
                                              HttpServletRequest request) {
        try {
            // Add request metadata
            loginRequest.setIpAddress(getClientIp(request));
            loginRequest.setUserAgent(request.getHeader("User-Agent"));

            // Authenticate user
            AuthResponse response = authService.authenticateUser(loginRequest);

            // Audit successful login
            auditService.logUserLogin(response.getUserId(), request);

            logger.info("User authenticated successfully: {}", loginRequest.getEmail());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Authentication failed for email: {}", loginRequest.getEmail(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Authentication failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh access token using refresh token")
    public ResponseEntity<?> refreshToken(@RequestHeader("Authorization") String refreshToken,
                                          HttpServletRequest request) {
        try {
            if (refreshToken != null && refreshToken.startsWith("Bearer ")) {
                refreshToken = refreshToken.substring(7);
            }

            AuthResponse response = authService.refreshToken(refreshToken);

            // Audit token refresh
            auditService.logTokenRefresh(response.getUserId(), request);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Token refresh failed", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Token refresh failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(error);
        }
    }

    @PostMapping("/logout")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Logout user and invalidate tokens")
    public ResponseEntity<?> logoutUser(@AuthenticationPrincipal CustomUserDetails userDetails,
                                        @RequestHeader("Authorization") String token,
                                        HttpServletRequest request) {
        try {
            if (token != null && token.startsWith("Bearer ")) {
                token = token.substring(7);
            }

            authService.logoutUser(userDetails.getId(), token);

            // Audit logout
            auditService.logUserLogout(userDetails.getId(), request);

            Map<String, String> response = new HashMap<>();
            response.put("message", "Logout successful");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Logout failed for user: {}", userDetails.getId(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Logout failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/verify-email/{token}")
    @Operation(summary = "Verify user email address")
    public ResponseEntity<?> verifyEmail(@PathVariable String token) {
        try {
            authService.verifyEmail(token);

            Map<String, String> response = new HashMap<>();
            response.put("message", "Email verified successfully");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Email verification failed for token: {}", token, e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Email verification failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/forgot-password")
    @Operation(summary = "Request password reset")
    public ResponseEntity<?> forgotPassword(@RequestBody Map<String, String> request,
                                            HttpServletRequest httpRequest) {
        try {
            String email = request.get("email");
            authService.initiatePasswordReset(email);

            // Audit password reset request
            auditService.logPasswordResetRequest(email, httpRequest);

            Map<String, String> response = new HashMap<>();
            response.put("message", "Password reset email sent if account exists");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            // Don't reveal if email exists or not
            logger.error("Password reset request failed", e);
            Map<String, String> response = new HashMap<>();
            response.put("message", "Password reset email sent if account exists");
            return ResponseEntity.ok(response);
        }
    }

    @PostMapping("/reset-password")
    @Operation(summary = "Reset password with token")
    public ResponseEntity<?> resetPassword(@RequestBody Map<String, String> request) {
        try {
            String token = request.get("token");
            String newPassword = request.get("newPassword");

            authService.resetPassword(token, newPassword);

            Map<String, String> response = new HashMap<>();
            response.put("message", "Password reset successfully");
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Password reset failed", e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Password reset failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @PostMapping("/enable-2fa")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Enable two-factor authentication")
    public ResponseEntity<?> enableTwoFactor(@AuthenticationPrincipal CustomUserDetails userDetails) {
        try {
            Map<String, String> response = authService.enableTwoFactorAuth(userDetails.getId());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("Failed to enable 2FA for user: {}", userDetails.getId(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "Failed to enable 2FA");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(error);
        }
    }

    @PostMapping("/verify-2fa")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Verify two-factor authentication code")
    public ResponseEntity<?> verifyTwoFactor(@AuthenticationPrincipal CustomUserDetails userDetails,
                                             @RequestBody Map<String, String> request) {
        try {
            String code = request.get("code");
            boolean verified = authService.verifyTwoFactorCode(userDetails.getId(), code);

            Map<String, Object> response = new HashMap<>();
            response.put("verified", verified);
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("2FA verification failed for user: {}", userDetails.getId(), e);
            Map<String, String> error = new HashMap<>();
            error.put("error", "2FA verification failed");
            error.put("message", e.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(error);
        }
    }

    @GetMapping("/me")
    @PreAuthorize("isAuthenticated()")
    @Operation(summary = "Get current user profile")
    public ResponseEntity<?> getCurrentUser(@AuthenticationPrincipal CustomUserDetails userDetails) {
        try {
            Map<String, Object> userInfo = new HashMap<>();
            userInfo.put("id", userDetails.getId());
            userInfo.put("email", userDetails.getEmail());
            userInfo.put("firstName", userDetails.getFirstName());
            userInfo.put("lastName", userDetails.getLastName());
            userInfo.put("emailVerified", userDetails.getEmailVerified());
            userInfo.put("authorities", userDetails.getAuthorities());

            return ResponseEntity.ok(userInfo);

        } catch (Exception e) {
            logger.error("Failed to get user info", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    private String getClientIp(HttpServletRequest request) {
        String xForwardedFor = request.getHeader("X-Forwarded-For");
        if (xForwardedFor != null && !xForwardedFor.isEmpty()) {
            return xForwardedFor.split(",")[0].trim();
        }

        String xRealIp = request.getHeader("X-Real-IP");
        if (xRealIp != null && !xRealIp.isEmpty()) {
            return xRealIp;
        }

        return request.getRemoteAddr();
    }
}