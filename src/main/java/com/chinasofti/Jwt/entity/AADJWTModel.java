package com.chinasofti.Jwt.entity;

public class AADJWTModel {

    private String token;
    private String tenantId;
    private String clientId;

    @Override
    public String toString() {
        return "AADJWT{" +
                "token='" + token + '\'' +
                ", tenantId='" + tenantId + '\'' +
                ", clientId='" + clientId + '\'' +
                '}';
    }

    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public String getTenantId() {
        return tenantId;
    }

    public void setTenantId(String tenantId) {
        this.tenantId = tenantId;
    }

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public AADJWTModel(String token) {
        this.token = token;
    }

    public String estimate(){
        if(token ==null || token==""){
            return "Please ensure the token is valid.";
        }
        if (tenantId == null || tenantId==""){
            return "Please ensure the tenanId is valid.";
        }
        if (clientId == null || tenantId==""){
            return "Please ensure the clientId is valid.";
        }

        return "";
    }
}
