/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class Resolution {
    private String last_resolved;
    private String ip_address;

    public String getLast_resolved() {
        return last_resolved;
    }

    public void setLast_resolved(String last_resolved) {
        this.last_resolved = last_resolved;
    }

    public String getIp_address() {
        return ip_address;
    }

    public void setIp_address(String ip_address) {
        this.ip_address = ip_address;
    }

}
