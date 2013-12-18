/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

import com.google.gson.annotations.SerializedName;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class URL {

    @SerializedName("url")
    private String url;
    @SerializedName("positives")
    private int positives;
    @SerializedName("total")
    private int total;
    @SerializedName("scan_date")
    private String scanDate;

    public String getUrl() {
        return url;
    }

    public void setUrl(String url) {
        this.url = url;
    }

    public int getPositives() {
        return positives;
    }

    public void setPositives(int positives) {
        this.positives = positives;
    }

    public int getTotal() {
        return total;
    }

    public void setTotal(int total) {
        this.total = total;
    }

    public String getScanDate() {
        return scanDate;
    }

    public void setScanDate(String scanDate) {
        this.scanDate = scanDate;
    }

}
