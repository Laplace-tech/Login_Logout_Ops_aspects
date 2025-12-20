package com.kyonggi.backend.auth.domain;

import jakarta.persistence.*;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Entity
@Table(name = "email_otp",
        uniqueConstraints = @UniqueConstraint(name = "uq_email_otp_email_purpose", columnNames = {"email", "purpose"}))
public class EmailOtp {

    @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String email;

    @Column(name = "code_hash", nullable = false, length = 100)
    private String codeHash;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private OtpPurpose purpose;

    @Column(name = "expires_at", nullable = false)
    private LocalDateTime expiresAt;

    @Column(name = "verified_at")
    private LocalDateTime verifiedAt;

    @Column(name = "failed_attempts", nullable = false)
    private int failedAttempts;

    @Column(name = "last_sent_at", nullable = false)
    private LocalDateTime lastSentAt;

    @Column(name = "resend_available_at", nullable = false)
    private LocalDateTime resendAvailableAt;

    @Column(name = "send_count_date", nullable = false)
    private LocalDate sendCountDate;

    @Column(name = "send_count", nullable = false)
    private int sendCount;

    protected EmailOtp() {}

    public static EmailOtp create(String email, String codeHash, OtpPurpose purpose,
                                  LocalDateTime expiresAt, LocalDateTime now, LocalDate today,
                                  LocalDateTime resendAvailableAt) {
        EmailOtp o = new EmailOtp();
        o.email = email;
        o.codeHash = codeHash;
        o.purpose = purpose;
        o.expiresAt = expiresAt;
        o.verifiedAt = null;
        o.failedAttempts = 0;
        o.lastSentAt = now;
        o.resendAvailableAt = resendAvailableAt;
        o.sendCountDate = today;
        o.sendCount = 1;
        return o;
    }

    public void reissue(String newCodeHash, LocalDateTime newExpiresAt, LocalDateTime now,
                        LocalDate today, LocalDateTime resendAvailableAt) {
        this.codeHash = newCodeHash;
        this.expiresAt = newExpiresAt;
        this.verifiedAt = null;
        this.failedAttempts = 0;

        if (!this.sendCountDate.equals(today)) {
            this.sendCountDate = today;
            this.sendCount = 0;
        }

        this.sendCount += 1;
        this.lastSentAt = now;
        this.resendAvailableAt = resendAvailableAt;
    }

    public boolean isExpired(LocalDateTime now) {
        return expiresAt.isBefore(now);
    }

    public boolean isVerified() {
        return verifiedAt != null;
    }

    public void markVerified(LocalDateTime now) {
        this.verifiedAt = now;
    }

    public void increaseFailure() {
        this.failedAttempts += 1;
    }

    // getters
    public String getEmail() { return email; }
    public String getCodeHash() { return codeHash; }
    public OtpPurpose getPurpose() { return purpose; }
    public LocalDateTime getExpiresAt() { return expiresAt; }
    public LocalDateTime getVerifiedAt() { return verifiedAt; }
    public int getFailedAttempts() { return failedAttempts; }
    public LocalDateTime getResendAvailableAt() { return resendAvailableAt; }
    public LocalDate getSendCountDate() { return sendCountDate; }
    public int getSendCount() { return sendCount; }
}
