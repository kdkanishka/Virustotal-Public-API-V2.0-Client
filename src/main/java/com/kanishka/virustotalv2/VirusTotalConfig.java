/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import java.net.InetSocketAddress;

/**
 * Configuration singleton which allows to maintain configurations
 * @author kdkanishka@gmail.com
 */
public final class VirusTotalConfig {

    private String virusTotalAPIKey;
    private static VirusTotalConfig configInstance = null;
    private InetSocketAddress proxy = null;

    private VirusTotalConfig() {
        virusTotalAPIKey = "";
    }

    public static VirusTotalConfig getConfigInstance() {
        if (configInstance == null) {
            synchronized (VirusTotalConfig.class) {
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

    public InetSocketAddress getProxy() {
        return proxy;
    }

    public void setProxy(InetSocketAddress proxy) {
        this.proxy = proxy;
    }
}
