/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

import com.google.gson.annotations.SerializedName;

/**
 * @author kdkanishka@gmail.com
 */
public class IPAddressReport {

    @SerializedName("undetected_downloaded_samples")
    private Sample[] undetectedDownloadedSamples;
    @SerializedName("detected_downloaded_samples")
    private Sample[] detectedDownloadedSamples;
    @SerializedName("resolutions")
    private Resolution[] resolutions;
    @SerializedName("detected_communicating_samples")
    private Sample[] detectedCommunicatingSamples;
    @SerializedName("undetected_communicating_samples")
    private Sample[] undetectedCommunicatingSamples;
    @SerializedName("detected_urls")
    private URL[] detectedUrls;
    @SerializedName("response_code")
    private int responseCode;
    @SerializedName("verbose_msg")
    private String verboseMessage;

    public Sample[] getUndetectedDownloadedSamples() {
        return undetectedDownloadedSamples;
    }

    public void setUndetectedDownloadedSamples(Sample[] undetectedDownloadedSamples) {
        System.arraycopy(undetectedDownloadedSamples, 0, this.undetectedDownloadedSamples, 0, undetectedDownloadedSamples.length);
    }

    public Sample[] getDetectedDownloadedSamples() {
        return detectedDownloadedSamples;
    }

    public void setDetectedDownloadedSamples(Sample[] detectedDownloadedSamples) {
        System.arraycopy(detectedDownloadedSamples, 0, this.detectedDownloadedSamples, 0, detectedDownloadedSamples.length);
    }

    public Resolution[] getResolutions() {
        return resolutions;
    }

    public void setResolutions(Resolution[] resolutions) {
        System.arraycopy(resolutions, 0, this.resolutions, 0, resolutions.length);
    }

    public Sample[] getDetectedCommunicatingSamples() {
        return detectedCommunicatingSamples;
    }

    public void setDetectedCommunicatingSamples(Sample[] detectedCommunicatingSamples) {
        System.arraycopy(detectedCommunicatingSamples, 0, this.detectedCommunicatingSamples, 0, detectedCommunicatingSamples.length);
    }

    public Sample[] getUndetectedCommunicatingSamples() {
        return undetectedCommunicatingSamples;
    }

    public void setUndetectedCommunicatingSamples(Sample[] undetectedCommunicatingSamples) {
        System.arraycopy(detectedCommunicatingSamples, 0, this.undetectedCommunicatingSamples, 0, undetectedCommunicatingSamples.length);
    }

    public URL[] getDetectedUrls() {
        return detectedUrls;
    }

    public void setDetectedUrls(URL[] detectedUrls) {
        System.arraycopy(detectedUrls, 0, this.detectedUrls, 0, detectedUrls.length);
    }

    public int getResponseCode() {
        return responseCode;
    }

    public void setResponseCode(int responseCode) {
        this.responseCode = responseCode;
    }

    public String getVerboseMessage() {
        return verboseMessage;
    }

    public void setVerboseMessage(String verboseMessage) {
        this.verboseMessage = verboseMessage;
    }
}