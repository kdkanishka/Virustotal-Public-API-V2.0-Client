/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kani.net;

import com.kanishka.net.exception.RequestNotComplete;
import com.kanishka.net.model.FormData;
import com.kanishka.net.model.Header;
import com.kanishka.net.model.MultiPartEntity;
import com.kanishka.net.model.RequestMethod;
import java.util.List;

/**
 *
 * @author kdkanishka@gmail.com
 */
public interface HTTPRequest {

    void addRequestHeaders(Header reqHeader);

    void setMethod(RequestMethod method);

    void addFormData(FormData formData);

    void addPart(MultiPartEntity part);

    void request(String urlStr) throws Exception;

    String getResponse() throws RequestNotComplete;

    List<Header> getResponseHeaders() throws RequestNotComplete;

    int getStatus() throws RequestNotComplete;
}
