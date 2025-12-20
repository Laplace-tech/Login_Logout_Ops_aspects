package com.kyonggi.backend.auth.domain;

import jakarta.persistence.*;

import java.time.LocalDateTime;

@Entity
@Table(name = "users", uniqueConstraints = {
        @UniqueConstraint(name = "uq_users_email", columnNames = "email"),
        @UniqueConstraint(name = "uq_users_nickname", columnNames = "nickname")
})
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 100)
    private String passwordHash;

    @Column(nullable = false, length = 30)
    private String nickname;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserRole role;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 20)
    private UserStatus status;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    protected User() {
    }

    public static User create(String email, String passwordHash, String nickname) {
        User u = new User();
        u.email = email;
        u.passwordHash = passwordHash;
        u.nickname = nickname;
        u.role = UserRole.USER;
        u.status = UserStatus.ACTIVE;
        u.lastLoginAt = null;
        return u;
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    public String getNickname() {
        return nickname;
    }
}
