/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

import com.google.gson.annotations.SerializedName;

import java.util.HashMap;

/**
 * @author kdkanishka@gmail.com
 */
public class FileScanReport {

    @SerializedName("scans")
    private HashMap<String, VirusScanInfo> scans;
    @SerializedName("scan_id")
    private String scanId;
    @SerializedName("sha1")
    private String sha1;
    @SerializedName("resource")
    private String resource;
    @SerializedName("response_code")
    private Integer responseCode;
    @SerializedName("scan_date")
    private String scanDate;
    @SerializedName("permalink")
    private String permalink;
    @SerializedName("verbose_msg")
    private String verboseMessage;
    @SerializedName("total")
    private Integer total;
    @SerializedName("positives")
    private Integer positives;
    @SerializedName("sha256")
    private String sha256;
    @SerializedName("md5")
    private String md5;

    public FileScanReport() {
    }

    public HashMap<String, VirusScanInfo> getScans() {
        return scans;
    }

    public void setScans(HashMap<String, VirusScanInfo> scans) {
        this.scans = scans;
    }

    public String getScanId() {
        return scanId;
    }

    public void setScanId(String scanId) {
        this.scanId = scanId;
    }

    /**
     * @return SHA1 hash value for the resource
     */
    public String getSha1() {
        return sha1;
    }

    public void setSha1(String sha1) {
        this.sha1 = sha1;
    }

    /**
     * Returns uniquely identifiable ID for the resource
     *
     * @return uniquely identifiable ID for the resource
     */
    public String getResource() {
        return resource;
    }

    public void setResource(String resource) {
        this.resource = resource;
    }

    /**
     * Retuns response code for the requested resource
     *
     * @return 1 if results are available for the requested resource otherwise
     * it will return 0
     */
    public Integer getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(Integer responseCode) {
        this.responseCode = responseCode;
    }

    /**
     * @return scanned date time
     */
    public String getScanDate() {
        return scanDate;
    }

    public void setScanDate(String scanDate) {
        this.scanDate = scanDate;
    }

    /**
     * @return permalink for the resource
     */
    public String getPermalink() {
        return permalink;
    }

    public void setPermalink(String permalink) {
        this.permalink = permalink;
    }

    /**
     * @return verbose message for the resource
     */
    public String getVerboseMessage() {
        return verboseMessage;
    }

    public void setVerboseMessage(String verboseMessage) {
        this.verboseMessage = verboseMessage;
    }

    /**
     * @return total number of scanners
     */
    public Integer getTotal() {
        return total;
    }

    public void setTotal(Integer total) {
        this.total = total;
    }

    /**
     * @return number of positives
     */
    public Integer getPositives() {
        return positives;
    }

    public void setPositives(Integer positives) {
        this.positives = positives;
    }

    /**
     * @return SHA256 hash for the resource
     */
    public String getSha256() {
        return sha256;
    }

    public void setSha256(String sha256) {
        this.sha256 = sha256;
    }

    /**
     * @return MD5 Hash for the resource
     */
    public String getMd5() {
        return md5;
    }

    public void setMd5(String md5) {
        this.md5 = md5;
    }
}
