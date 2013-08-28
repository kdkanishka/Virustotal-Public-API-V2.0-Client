/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto.domain;

import java.util.HashMap;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class DomainReport {
    private Sample[] undetected_download_samples;
    private Sample[] detected_download_samples;
    private Resolution[] resolutions;
    private Sample[] detected_communicating_samples;
    private Sample[] undetected_communicating_samples;
    private URL[] detected_urls;
    private int response_code;
    private String verbose_msg;

    public Sample[] getUndetected_download_samples() {
        return undetected_download_samples;
    }

    public void setUndetected_download_samples(Sample[] undetected_download_samples) {
        this.undetected_download_samples = undetected_download_samples;
    }

    public Sample[] getDetected_download_samples() {
        return detected_download_samples;
    }

    public void setDetected_download_samples(Sample[] detected_download_samples) {
        this.detected_download_samples = detected_download_samples;
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
