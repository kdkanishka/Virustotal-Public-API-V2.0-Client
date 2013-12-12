/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.model;

import java.io.Serializable;

/**
 * Represents HTTP header
 *
 * @author kdkanishka@gmail.com
 */
public class Header implements Serializable {

    private String key;
    private String value;

    public Header() {
    }

    public Header(String key, String value) {
        this.key = key;
        this.value = value;
    }

    public String getKey() {
        return key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
