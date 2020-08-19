package com.chinasofti.Jwt.entity;

import org.jose4j.jwk.JsonWebKey;

import java.util.Date;
import java.util.List;

public class KeyWithTTL {
    private Date expirationDate;
    private List<JsonWebKey> keys;

    @Override
    public String toString() {
        return "KeyWithTTL{" +
                "expirationDate=" + expirationDate +
                ", keys=" + keys +
                '}';
    }

    public Date getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate;
    }

    public List<JsonWebKey> getKeys() {
        return keys;
    }

    public void setKeys(List<JsonWebKey> keys) {
        this.keys = keys;
    }

    public KeyWithTTL() {
    }

    public KeyWithTTL(Date expirationDate) {
        this.expirationDate = expirationDate;
    }
}
