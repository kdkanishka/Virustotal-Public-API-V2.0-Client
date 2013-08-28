/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class GeneralResponse {
    private int response_code;
    private String verbose_msg;

    public int getResponse_code() {
        return response_code;
    }

    public void setResponse_code(int response_code) {
        this.response_code = response_code;
    }

    public String getVerbose_msg() {
        return verbose_msg;
    }

    public void setVerbose_msg(String verbose_msg) {
        this.verbose_msg = verbose_msg;
    }
}
