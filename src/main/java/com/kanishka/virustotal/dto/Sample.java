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
public class Sample {

    @SerializedName("date")
    private String date;
    @SerializedName("positives")
    private int positives;
    @SerializedName("total")
    private int total;
    @SerializedName("sha256")
    private String sha256;

    public String getDate() {
        return date;
    }

    public void setDate(String date) {
        this.date = date;
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

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }
}
