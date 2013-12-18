/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * @author kdkanishka@gmail.com
 */
public class Resolution {

    @SerializedName("last_resolved")
    private String lastResolved;
    @SerializedName("ip_address")
    private String ipAddress;

    public String getLastResolved() {
        return lastResolved;
    }

    public void setLastResolved(String lastResolved) {
        this.lastResolved = lastResolved;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

}
