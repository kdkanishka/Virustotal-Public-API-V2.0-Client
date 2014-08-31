/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.commons;

import com.kanishka.net.exception.RequestNotComplete;
import com.kanishka.net.model.FormData;
import com.kanishka.net.model.Header;
import com.kanishka.net.model.HttpStatus;
import com.kanishka.net.model.MultiPartEntity;
import com.kanishka.net.model.RequestMethod;
import com.kanishka.net.model.Response;
import org.apache.http.entity.mime.HttpMultipartMode;
import org.apache.http.entity.mime.MultipartEntity;

import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * @author kdkanishka@gmail.com
 */
public class BasicHTTPRequestImpl implements HTTPRequest {

    public BasicHTTPRequestImpl() {

    }

    @Override
    public final Response request(final String url,
                                  final List<Header> reqHeaders,
                                  final List<FormData> formData,
                                  final RequestMethod requestMethod,
                                  final List<MultiPartEntity> multiParts
    ) throws RequestNotComplete , IOException{
        HttpStatus httpStatus = new HttpStatus();
        List<Header> respoHeaders = new ArrayList<Header>();
        StringBuilder response = new StringBuilder();
        Response responseWrapper;

        URL urlObj = new URL(url);
        HttpURLConnection conn = (HttpURLConnection) urlObj.openConnection();
        conn.setRequestMethod(requestMethod.toString());

        if (reqHeaders != null && reqHeaders.size() > 0) {
            Iterator<Header> itrHeaders = reqHeaders.iterator();
            while (itrHeaders.hasNext()) {
                Header reqHdr = itrHeaders.next();
                conn.setRequestProperty(reqHdr.getKey(), reqHdr.getValue());
            }
        }

        //add multipart entities
        if (multiParts != null && multiParts.size() > 0) {
            MultipartEntity multipartEntity =
                    new MultipartEntity(HttpMultipartMode.STRICT);
            for (MultiPartEntity part : multiParts) {
                multipartEntity.addPart(part.getPartName(), part.getEntity());
            }
            conn.setDoOutput(true);
            conn.setRequestProperty("Content-Type",
                    multipartEntity.getContentType().getValue());

            //try to write to the output stream of the connection
            OutputStream outStream = conn.getOutputStream();
            multipartEntity.writeTo(outStream);
            outStream.close();
        } else {
            //add form data to the request
            if (formData != null && formData.size() > 0) {
                Iterator<FormData> itrFormData = formData.iterator();
                StringBuilder content = new StringBuilder();
                while (itrFormData.hasNext()) {
                    FormData formDataObj = itrFormData.next();
                    content.append(URLEncoder.encode(formDataObj.getKey(),
                            "UTF-8"));
                    content.append("=");
                    content.append(URLEncoder.encode(formDataObj.getValue(),
                            "UTF-8"));
                    content.append("&");
                }
                if (content.length() > 0) {
                    conn.setDoOutput(true);
                    //Send request
                    DataOutputStream wr =
                            new DataOutputStream(conn.getOutputStream());
                    wr.writeBytes(content.toString());
                    wr.flush();
                    wr.close();
                }
            }
        }

        //fetch response headers
        Map<String, List<String>> rowHeaders = conn.getHeaderFields();
        Iterator<String> keys = rowHeaders.keySet().iterator();
        while (keys.hasNext()) {
            String key = keys.next();
            List<String> vals = rowHeaders.get(key);
            if (vals.size() > 0) {
                respoHeaders.add(new Header(key, vals.get(0)));
            }
        }

        //Get Response
        try {
            InputStream is = conn.getInputStream();
            BufferedReader rd = new BufferedReader(new InputStreamReader(is));
            String line;
            while ((line = rd.readLine()) != null) {
                response.append(line);
                response.append('\r');
            }
            httpStatus.setStatusCode(conn.getResponseCode());
            httpStatus.setStatusCode(conn.getResponseCode());
            httpStatus.setMessage(conn.getResponseMessage());
            is.close();
            rd.close();
            conn.disconnect();
        } catch (Throwable e) {
            httpStatus.setStatusCode(conn.getResponseCode());
            httpStatus.setStatusCode(conn.getResponseCode());
            httpStatus.setMessage(conn.getResponseMessage());
            throw new RequestNotComplete("Could not complete the request",e,
                    httpStatus);
        }
        responseWrapper = new Response(httpStatus.getStatusCode(),
                response.toString(),respoHeaders);
        return responseWrapper;
    }
}
