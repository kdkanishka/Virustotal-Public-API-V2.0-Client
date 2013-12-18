/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * @author kdkanishka@gmail.com
 */
public class ScanInfo {

    @SerializedName("scan_id")
    private String scanId;
    @SerializedName("sha1")
    private String sha1;
    @SerializedName("resource")
    private String resource;
    @SerializedName("response_code")
    private int responseCode;
    @SerializedName("sha256")
    private String sha256;
    @SerializedName("permalink")
    private String permalink;
    @SerializedName("md5")
    private String md5;
    @SerializedName("verbose_msg")
    private String verboseMessage;
    @SerializedName("scan_date")
    private String scanDate;

    public ScanInfo() {
    }

    /**
     * @return unique id to identify the scan
     */
    public String getScanId() {
        return scanId;
    }

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    /**
     * @return SHA1 hash for the scanned file
     */
    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    /**
     * @return unique ID for the scanned resource
     */
    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    /**
     * @return response code for the request
     */
    public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    public String getPermalink() {
        return permalink;
    }

    public void setPermalink(String permalink) {
        this.permalink = permalink;
    }

    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }

    public String getVerboseMessage() {
        return verboseMessage;
    }

    public void setVerboseMessage(String verboseMessage) {
        this.verboseMessage = verboseMessage;
    }

    public String getScanDate() {
        return scanDate;
    }

    public void setScanDate(String scanDate) {
        this.scanDate = scanDate;
    }
}
