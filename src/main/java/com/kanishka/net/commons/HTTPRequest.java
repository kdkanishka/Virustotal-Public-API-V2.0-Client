/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.commons;

import com.kanishka.net.model.FormData;
import com.kanishka.net.model.Header;
import com.kanishka.net.model.HttpStatus;
import com.kanishka.net.model.MultiPartEntity;
import com.kanishka.net.model.RequestMethod;
import com.kanishka.net.model.Response;

import java.io.IOException;
import java.util.List;

/**
 * @author kdkanishka@gmail.com
 */
public interface HTTPRequest {

    Response request(String urlStr, List<Header> reqHeaders, List<FormData> formData,
                     RequestMethod requestMethod, List<MultiPartEntity> multiParts, HttpStatus httpStatus) throws IOException;
}
