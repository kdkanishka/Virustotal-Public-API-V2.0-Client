/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.exception;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class QuotaExceededException extends Exception {

    public QuotaExceededException() {
    }

    public QuotaExceededException(String string) {
        super(string);
    }

    public QuotaExceededException(String string, Throwable thrwbl) {
        super(string, thrwbl);
    }

    public QuotaExceededException(Throwable thrwbl) {
        super(thrwbl);
    }
}
