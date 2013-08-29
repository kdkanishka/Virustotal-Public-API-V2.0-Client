/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.commons;

import com.google.gson.Gson;
import com.kanishka.net.exception.RequestNotComplete;
import com.kanishka.net.model.FormData;
import com.kanishka.net.model.Header;
import com.kanishka.net.model.RequestMethod;
import httpbin.HttpBinResponse;
import org.junit.After;
import static org.junit.Assert.*;
import org.junit.Before;
import org.junit.Test;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class BasicHTTPRequestImplTest {

    private Gson gsonParser;

    public BasicHTTPRequestImplTest() {
    }

    @Before
    public void setUp() {
        gsonParser = new Gson();
    }

    @After
    public void tearDown() {
        gsonParser = null;
        System.gc();
    }

    @Test
    public void testConstructor() throws RequestNotComplete {
        System.out.println("Testing BasicHTTPRequestImpl constructor");
        BasicHTTPRequestImpl instance = new BasicHTTPRequestImpl();
        try {
            instance.getResponse();
            fail("invoked getResponse but it didn't throw expceted RequestNotComplete exception!");
        } catch (RequestNotComplete expected) {
            assertTrue(expected.getMessage().length() > 0);
        } catch (Exception notExpected) {
            fail("threw a Wrong exception!");
        }
        try {
            instance.getResponseHeaders();
            fail("invoked getResponseHeaders but it didn't throw expceted RequestNotComplete exception!");
        } catch (RequestNotComplete expected) {
            assertTrue(expected.getMessage().length() > 0);
        } catch (Exception notExpected) {
            fail("threw a Wrong exception!");
        }
        try {
            instance.getStatus();
            fail("invoked getStatus but it didn't throw expceted RequestNotComplete exception!");
        } catch (RequestNotComplete expected) {
            assertTrue(expected.getMessage().length() > 0);
        } catch (Exception notExpected) {
            fail("threw a Wrong exception!");
        }
    }

    @Test(timeout=15000)
    public void testSimpleGetMethod() throws Exception {
        System.out.println("Testing a simple GET method...");
        BasicHTTPRequestImpl request = new BasicHTTPRequestImpl();
        String arg1 = "val1";
        String arg2 = "val2";
        String uri = "http://httpbin.org/get?arg1=" + arg1 + "&arg2=" + arg2;
        request.setMethod(RequestMethod.GET);
        request.request(uri);
        String response = request.getResponse();
        assertTrue(request.getStatus() == 200);
        assertTrue(response.length() > 0);
        HttpBinResponse httpBinRespObj = gsonParser.fromJson(response, HttpBinResponse.class);
        assertEquals(httpBinRespObj.getArgs().get("arg1"), arg1);
        assertEquals(httpBinRespObj.getArgs().get("arg2"), arg2);
        assertTrue(httpBinRespObj.getOrigin().length() > 0);
    }

    @Test(timeout=15000)
    public void testSimpleGetMethodWithArgumentsAndHeaders() throws Exception {
        System.out.println("Testing a simple GET method with arguments and headers.");
        BasicHTTPRequestImpl request = new BasicHTTPRequestImpl();
        String header1 = "HEADER1";
        String header2 = "HEADER2";
        String arg1 = "val1";
        String arg2 = "val2";
        String uri = "http://httpbin.org/get?arg1=" + arg1 + "&arg2=" + arg2;
        request.addRequestHeaders(new Header("Header1", header1));
        request.addRequestHeaders(new Header("Header2", header2));
        request.setMethod(RequestMethod.GET);
        request.request(uri);
        String response = request.getResponse();
        assertTrue(request.getStatus() == 200);
        assertTrue(response.length() > 0);
        HttpBinResponse httpBinRespObj = gsonParser.fromJson(response, HttpBinResponse.class);
        assertEquals(httpBinRespObj.getArgs().get("arg1"), arg1);
        assertEquals(httpBinRespObj.getArgs().get("arg2"), arg2);
        assertTrue(httpBinRespObj.getOrigin().length() > 0);
        assertEquals(httpBinRespObj.getHeaders().get("Header1"), header1);
        assertEquals(httpBinRespObj.getHeaders().get("Header2"), header2);
    }

    @Test(timeout=15000)
    public void testSimplePostMehod() throws Exception {
        System.out.println("Testing a simple POST method.");
        BasicHTTPRequestImpl request = new BasicHTTPRequestImpl();
        String formdata1 = "fromdata1";
        String formdata2 = "fromdata2";
        String uri = "http://httpbin.org/post";
        request.addFormData(new FormData("formdata1", formdata1));
        request.addFormData(new FormData("formdata2", formdata2));
        request.setMethod(RequestMethod.POST);
        request.request(uri);
        String response = request.getResponse();
        assertTrue(request.getStatus() == 200);
        assertTrue(response.length() > 0);
        HttpBinResponse httpBinRespObj = gsonParser.fromJson(response, HttpBinResponse.class);
        assertEquals(httpBinRespObj.getForm().get("formdata1"), formdata1);
        assertEquals(httpBinRespObj.getForm().get("formdata2"), formdata2);
    }
    
    @Test(timeout=15000)
    public void testSimplePostMethodWithHeaders() throws Exception{
        System.out.println("Testing a simple POST method with form data.");
        BasicHTTPRequestImpl request = new BasicHTTPRequestImpl();
        String formdata1 = "fromdata1";
        String formdata2 = "fromdata2";
        String header1="header1";
        String header2="header2";
        String uri = "http://httpbin.org/post";
        request.addRequestHeaders(new Header("Header1", header1));
        request.addRequestHeaders(new Header("Header2", header2));
        request.addFormData(new FormData("formdata1", formdata1));
        request.addFormData(new FormData("formdata2", formdata2));
        request.setMethod(RequestMethod.POST);
        request.request(uri);
        String response = request.getResponse();
        assertTrue(request.getStatus() == 200);
        assertTrue(response.length() > 0);
        HttpBinResponse httpBinRespObj = gsonParser.fromJson(response, HttpBinResponse.class);
        assertEquals(httpBinRespObj.getHeaders().get("Header1"), header1);
        assertEquals(httpBinRespObj.getHeaders().get("Header2"), header2);
        assertEquals(httpBinRespObj.getForm().get("formdata1"), formdata1);
        assertEquals(httpBinRespObj.getForm().get("formdata2"), formdata2);
    }
}
