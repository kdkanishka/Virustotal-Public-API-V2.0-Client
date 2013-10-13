/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.dto;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class DomainReport {

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
        System.arraycopy(undetected_downloaded_samples, 0, this.undetected_communicating_samples, 0, undetected_downloaded_samples.length);
    }

    public Sample[] getDetected_downloaded_samples() {
        return detected_downloaded_samples;
    }

    public void setDetected_downloaded_samples(Sample[] detected_downloaded_samples) {
        System.arraycopy(detected_downloaded_samples, 0, this.detected_downloaded_samples, 0, detected_downloaded_samples.length);
    }

    public Resolution[] getResolutions() {
        return resolutions;
    }

    public void setResolutions(Resolution[] resolutions) {
        System.arraycopy(resolutions, 0, this.resolutions, 0, resolutions.length);
    }

    public Sample[] getDetected_communicating_samples() {
        return detected_communicating_samples;
    }

    public void setDetected_communicating_samples(Sample[] detected_communicating_samples) {
        System.arraycopy(detected_communicating_samples, 0, this.detected_communicating_samples, 0, detected_communicating_samples.length);
    }

    public Sample[] getUndetected_communicating_samples() {
        return undetected_communicating_samples;
    }

    public void setUndetected_communicating_samples(Sample[] undetected_communicating_samples) {
        System.arraycopy(undetected_communicating_samples, 0, this.undetected_communicating_samples, 0, undetected_communicating_samples.length);
    }

    public URL[] getDetected_urls() {
        return detected_urls;
    }

    public void setDetected_urls(URL[] detected_urls) {
        System.arraycopy(detected_urls, 0, this.detected_urls, 0, detected_urls.length);
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
