/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * @author kdkanishka@gmail.com
 */
public class VirusScanInfo {

    @SerializedName("detected")
    private boolean detected;
    @SerializedName("version")
    private String version;
    @SerializedName("result")
    private String result;
    @SerializedName("update")
    private String update;

    public VirusScanInfo() {
    }

    public boolean isDetected() {
        return detected;
    }

    public void setDetected(boolean detected) {
        this.detected = detected;
    }

    public String getVersion() {
        return version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getUpdate() {
        return update;
    }

    public void setUpdate(String update) {
        this.update = update;
    }
}
