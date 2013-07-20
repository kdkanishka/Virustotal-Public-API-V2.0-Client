/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.exception;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class UnauthorizedAccessException extends Exception {

    public UnauthorizedAccessException() {
    }

    public UnauthorizedAccessException(String string) {
        super(string);
    }

    public UnauthorizedAccessException(String string, Throwable thrwbl) {
        super(string, thrwbl);
    }

    public UnauthorizedAccessException(Throwable thrwbl) {
        super(thrwbl);
    }
}
