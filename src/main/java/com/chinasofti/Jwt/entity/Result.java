package com.chinasofti.Jwt.entity;

/**
 * the result of operation
 */
public class Result {

    // the status of operation
    public Boolean status;
    // the message of operation
    public String message;

    @Override
    public String toString() {
        return "Result{" +
                "status=" + status +
                ", message='" + message + '\'' +
                '}';
    }

    public Boolean getStatus() {
        return status;
    }

    public void setStatus(Boolean status) {
        this.status = status;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public Result() {
    }

    public Result(Boolean status) {
        this.status = status;
    }
}
