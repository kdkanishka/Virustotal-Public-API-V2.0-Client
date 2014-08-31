/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.exception;

import com.kanishka.net.model.HttpStatus;

/**
 * @author kdkanishka@gmail.com
 */
public class RequestNotComplete extends Exception {

    private HttpStatus httpStatus;

    public RequestNotComplete(HttpStatus httpStatus) {
        this.httpStatus = httpStatus;
    }

    public RequestNotComplete(String message, HttpStatus httpStatus) {
        super(message);
        this.httpStatus = httpStatus;
    }

    public RequestNotComplete(String message, Throwable cause, HttpStatus httpStatus) {
        super(message, cause);
        this.httpStatus = httpStatus;
    }

    public RequestNotComplete(Throwable cause, HttpStatus httpStatus) {
        super(cause);
        this.httpStatus = httpStatus;
    }

    public HttpStatus getHttpStatus() {
        return httpStatus;
    }
}
