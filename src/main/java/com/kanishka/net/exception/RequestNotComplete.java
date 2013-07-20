/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.exception;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class RequestNotComplete extends Exception {

    public RequestNotComplete() {
    }

    public RequestNotComplete(String message) {
        super(message);
    }

    public RequestNotComplete(String message, Throwable cause) {
        super(message, cause);
    }

    public RequestNotComplete(Throwable cause) {
        super(cause);
    }
}
