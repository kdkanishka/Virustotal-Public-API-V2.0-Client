package com.kanishka.net.model;

/**
 * Created by kanishka on 12/12/13.
 */
public class HttpStatus {
    private int statusCode = -1;
    private String message;

    public HttpStatus() {
    }

    public HttpStatus(int statusCode, String message) {
        this.statusCode = statusCode;
        this.message = message;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public void setStatusCode(int statusCode) {
        this.statusCode = statusCode;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
