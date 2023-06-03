package com.example.security_jwt.model;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import java.sql.Timestamp;

@Entity
@Data
@NoArgsConstructor
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private int id;
    private String userName;
    private String password;
    private String email;
    private String role;            // ROLE_USER, ROLE_ADMIN
    private String provider;        // 예) google
    private String providerId;
    @CreationTimestamp
    private Timestamp createDate;

    @Builder
    public User(String userName, String password, String email, String role, String provider, String providerId, Timestamp createDate) {
        this.userName = userName;
        this.password = password;
        this.email = email;
        this.role = role;
        this.provider = provider;
        this.providerId = providerId;
        this.createDate = createDate;
    }
}
