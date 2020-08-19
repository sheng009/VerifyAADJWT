package com.chinasofti.Jwt.constraint;

public final class CacheKeysConstraint {
    private CacheKeysConstraint() {
    }

    public static String SIGNING_KEYS = "_SigningKeys_[tenantId]_[clientId]";
}
