/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.model;

import java.io.Serializable;
import java.util.List;

/**
 *
 * @author kanishka
 */
public class Response implements Serializable {

    private int status;
    private String response;
    private List<Header> respoHeaders;

    public Response() {
    }

    public Response(int status, String resopnse, List<Header> respoHeaders) {
        this.status = status;
        this.response = resopnse;
        this.respoHeaders = respoHeaders;
    }

    public int getStatus() {
        return status;
    }

    public void setStatus(int status) {
        this.status = status;
    }

    public String getResponse() {
        return response;
    }

    public void setResponse(String response) {
        this.response = response;
    }

    public List<Header> getRespoHeaders() {
        return respoHeaders;
    }

    public void setRespoHeaders(List<Header> respoHeaders) {
        this.respoHeaders = respoHeaders;
    }
}
