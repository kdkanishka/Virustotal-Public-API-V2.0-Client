/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class IPAddressReport {
    private Sample[] undetected_downloaded_samples;
    private Sample[] detected_downloaded_samples;
    private Resolution[] resolutions;
    private Sample[] detected_communicating_samples;
    private Sample[] undetected_communicating_samples;
    private URL[] detected_urls;
    private int response_code;
    private String verbose_msg;

    public Sample[] getUndetected_downloaded_samples() {
        return undetected_downloaded_samples;
    }

    public void setUndetected_downloaded_samples(Sample[] undetected_downloaded_samples) {
        this.undetected_downloaded_samples = undetected_downloaded_samples;
    }

    public Sample[] getDetected_downloaded_samples() {
        return detected_downloaded_samples;
    }

    public void setDetected_downloaded_samples(Sample[] detected_downloaded_samples) {
        this.detected_downloaded_samples = detected_downloaded_samples;
    }

    public Resolution[] getResolutions() {
        return resolutions;
    }

    public void setResolutions(Resolution[] resolutions) {
        this.resolutions = resolutions;
    }

    public Sample[] getDetected_communicating_samples() {
        return detected_communicating_samples;
    }

    public void setDetected_communicating_samples(Sample[] detected_communicating_samples) {
        this.detected_communicating_samples = detected_communicating_samples;
    }

    public Sample[] getUndetected_communicating_samples() {
        return undetected_communicating_samples;
    }

    public void setUndetected_communicating_samples(Sample[] undetected_communicating_samples) {
        this.undetected_communicating_samples = undetected_communicating_samples;
    }

    public URL[] getDetected_urls() {
        return detected_urls;
    }

    public void setDetected_urls(URL[] detected_urls) {
        this.detected_urls = detected_urls;
    }

    public int getResponse_code() {
        return response_code;
    }

    public void setResponse_code(int response_code) {
        this.response_code = response_code;
    }

    public String getVerbose_msg() {
        return verbose_msg;
    }

    public void setVerbose_msg(String verbose_msg) {
        this.verbose_msg = verbose_msg;
    }
    
}