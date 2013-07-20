/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.exception;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class APIKeyNotFoundException extends Exception {

    public APIKeyNotFoundException() {
    }

    public APIKeyNotFoundException(String string) {
        super(string);
    }

    public APIKeyNotFoundException(String string, Throwable thrwbl) {
        super(string, thrwbl);
    }

    public APIKeyNotFoundException(Throwable thrwbl) {
        super(thrwbl);
    }
}
