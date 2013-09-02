/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotal.config;

/**
 * Configuration singleton which allows to maintain configurations
 * @author kdesilva
 */
public class VirusTotalConfig {

    private String virusTotalAPIKey;
    private static VirusTotalConfig configInstance = null;

    private VirusTotalConfig() {
        virusTotalAPIKey = "";
    }

    public static VirusTotalConfig getConfigInstance() {
        if (configInstance == null) {
            synchronized (configInstance) {
                if (configInstance == null) {
                    configInstance = new VirusTotalConfig();
                }
            }
        }

        return configInstance;
    }

    public String getVirusTotalAPIKey() {
        return virusTotalAPIKey;
    }

    public void setVirusTotalAPIKey(String virusTotalAPIKey) {
        this.virusTotalAPIKey = virusTotalAPIKey;
    }

}
