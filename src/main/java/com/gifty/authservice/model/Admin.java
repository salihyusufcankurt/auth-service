package com.gifty.authservice.model;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Entity
@DiscriminatorValue("ADMIN")
@Getter
@Setter
public class Admin extends User {
    private String adminSpecificField;

    @Override
    public String getType() {
        return "ADMIN";
    }
}