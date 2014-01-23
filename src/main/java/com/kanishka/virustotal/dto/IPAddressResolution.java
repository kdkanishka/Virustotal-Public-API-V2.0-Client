package com.kanishka.virustotal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * Created by kanishka on 1/23/14.
 */
public class IPAddressResolution {

    @SerializedName("last_resolved")
    private String lastResolved;
    @SerializedName("hostname")
    private String hostName;

    public String getLastResolved() {
        return lastResolved;
    }

    public void setLastResolved(String lastResolved) {
        this.lastResolved = lastResolved;
    }

    public String getHostName() {
        return hostName;
    }

    public void setHostName(String hostName) {
        this.hostName = hostName;
    }
}
