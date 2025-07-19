package com.zerotrace.dto.response;
import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.LocalDateTime;

@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuthResponse {

    private String accessToken;
    private String refreshToken;
    private String tokenType = "Bearer";
    private Long expiresIn;
    private Long userId;
    private String email;
    private String firstName;
    private String lastName;
    private Boolean twoFactorRequired;
    private Boolean emailVerified;
    private LocalDateTime lastLogin;

    // Constructors
    public AuthResponse() {}

    public AuthResponse(String accessToken, String refreshToken, Long expiresIn) {
        this.accessToken = accessToken;
        this.refreshToken = refreshToken;
        this.expiresIn = expiresIn;
    }

    // Builder pattern for convenience
    public static class Builder {
        private AuthResponse response = new AuthResponse();

        public Builder accessToken(String token) {
            response.accessToken = token;
            return this;
        }

        public Builder refreshToken(String token) {
            response.refreshToken = token;
            return this;
        }

        public Builder expiresIn(Long expiresIn) {
            response.expiresIn = expiresIn;
            return this;
        }

        public Builder userId(Long userId) {
            response.userId = userId;
            return this;
        }

        public Builder email(String email) {
            response.email = email;
            return this;
        }

        public Builder firstName(String firstName) {
            response.firstName = firstName;
            return this;
        }

        public Builder lastName(String lastName) {
            response.lastName = lastName;
            return this;
        }

        public Builder twoFactorRequired(Boolean required) {
            response.twoFactorRequired = required;
            return this;
        }

        public Builder emailVerified(Boolean verified) {
            response.emailVerified = verified;
            return this;
        }

        public Builder lastLogin(LocalDateTime lastLogin) {
            response.lastLogin = lastLogin;
            return this;
        }

        public AuthResponse build() {
            return response;
        }
    }

    // Getters and Setters
    public String getAccessToken() { return accessToken; }
    public void setAccessToken(String accessToken) { this.accessToken = accessToken; }

    public String getRefreshToken() { return refreshToken; }
    public void setRefreshToken(String refreshToken) { this.refreshToken = refreshToken; }

    public String getTokenType() { return tokenType; }
    public void setTokenType(String tokenType) { this.tokenType = tokenType; }

    public Long getExpiresIn() { return expiresIn; }
    public void setExpiresIn(Long expiresIn) { this.expiresIn = expiresIn; }

    public Long getUserId() { return userId; }
    public void setUserId(Long userId) { this.userId = userId; }

    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    public String getFirstName() { return firstName; }
    public void setFirstName(String firstName) { this.firstName = firstName; }

    public String getLastName() { return lastName; }
    public void setLastName(String lastName) { this.lastName = lastName; }

    public Boolean getTwoFactorRequired() { return twoFactorRequired; }
    public void setTwoFactorRequired(Boolean twoFactorRequired) { this.twoFactorRequired = twoFactorRequired; }

    public Boolean getEmailVerified() { return emailVerified; }
    public void setEmailVerified(Boolean emailVerified) { this.emailVerified = emailVerified; }

    public LocalDateTime getLastLogin() { return lastLogin; }
    public void setLastLogin(LocalDateTime lastLogin) { this.lastLogin = lastLogin; }
}