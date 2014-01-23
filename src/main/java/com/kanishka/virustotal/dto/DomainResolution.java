package com.kanishka.virustotal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * Created by kanishka on 1/23/14.
 */
public class DomainResolution {

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
