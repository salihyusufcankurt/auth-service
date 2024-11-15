package com.gifty.authservice.model;

import com.fasterxml.jackson.annotation.JsonSubTypes;
import com.fasterxml.jackson.annotation.JsonTypeInfo;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;

import java.util.HashMap;
import java.util.Map;

@Entity
@Inheritance(strategy = InheritanceType.SINGLE_TABLE)
@DiscriminatorColumn(name = "user_type", discriminatorType = DiscriminatorType.STRING)
@Table(name = "`user`") // Tırnak işaretleriyle 'user' tablosu
@Getter
@Setter
@JsonTypeInfo(
        use = JsonTypeInfo.Id.NAME, // JSON içinde bir "type" alanı bekler
        include = JsonTypeInfo.As.PROPERTY,
        property = "type" // JSON'da alt sınıfı belirtecek alanın adı
)
@JsonSubTypes({
        @JsonSubTypes.Type(value = Admin.class, name = "admin"),
        @JsonSubTypes.Type(value = Customer.class, name = "customer")
})
public abstract class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String username;

    @Column(nullable = false)
    private String password;

    @Column(nullable = false, unique = true)
    private String email;

    @Column(nullable = false)
    public abstract String getType();

    @ElementCollection
    @Column(nullable = false)
    private Map<String, String> deviceTokens = new HashMap<>(); // Cihaz ID - Token eşleşmesi

    @Column(nullable = true)
    private String lastUsedIp; // Son kullanılan IP adresi


}
