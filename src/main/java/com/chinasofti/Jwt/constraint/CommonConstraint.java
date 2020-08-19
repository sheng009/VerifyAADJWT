package com.chinasofti.Jwt.constraint;


public final class CommonConstraint {
    private CommonConstraint() {
    }

    public static String STS_DISCOVERY_ENDPOINT = "https://login.microsoftonline.com/{tenantId}/v2.0/.well-known/openid-configuration";
    public static String EXPECTED_AUDIENCE = "api://faa0afb8-bfe5-4648-82e9-c6f3b909fcf4";
}
