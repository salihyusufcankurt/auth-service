package com.gifty.authservice.model;

import jakarta.persistence.DiscriminatorValue;
import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Entity
@DiscriminatorValue("CUSTOMER")
@Getter
@Setter
public class Customer extends User {
    private String customerSpecificField;

    @Override
    public String getType() {
        return "CUSTOMER";
    }
}