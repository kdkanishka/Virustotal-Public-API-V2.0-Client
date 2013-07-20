/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.exception;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class InvalidArguentsException extends Exception {

    public InvalidArguentsException() {
    }

    public InvalidArguentsException(String string) {
        super(string);
    }

    public InvalidArguentsException(String string, Throwable thrwbl) {
        super(string, thrwbl);
    }

    public InvalidArguentsException(Throwable thrwbl) {
        super(thrwbl);
    }
}
