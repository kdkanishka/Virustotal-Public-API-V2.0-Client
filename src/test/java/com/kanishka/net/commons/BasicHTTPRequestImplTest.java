/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.net.commons;

import com.google.gson.Gson;
import com.kanishka.net.exception.RequestNotComplete;
import com.kanishka.net.model.FormData;
import com.kanishka.net.model.Header;
import com.kanishka.net.model.MultiPartEntity;
import com.kanishka.net.model.RequestMethod;
import httpbin.HttpBinResponse;
import java.util.List;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

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

    @Test
    public void testSimpleGetMethod() throws Exception {
        System.out.println("Testing a simple GET method...");
        BasicHTTPRequestImpl request = new BasicHTTPRequestImpl();
        String arg1 = "val1";
        String arg2 = "val2";
        String uri = "http://httpbin.org/get?arg1=" + arg1 + "&arg2=" + arg2;
        request.setMethod(RequestMethod.GET);
        request.request(uri);
        String response = request.getResponse();
        assertTrue(response.length() > 0);
        HttpBinResponse httpBinRespObj = gsonParser.fromJson(response, HttpBinResponse.class);
        assertEquals(httpBinRespObj.getArgs().get("arg1"), arg1);
        assertEquals(httpBinRespObj.getArgs().get("arg2"), arg2);
        assertTrue(httpBinRespObj.getOrigin().length() > 0);
    }

    @Test
    public void testSimpleGetMethodWithArgumentsAndHeaders() throws Exception {
        System.out.println("Testing a simple GET method with arguments and headers.");
        BasicHTTPRequestImpl request = new BasicHTTPRequestImpl();
        String header1="HEADER1";
        String header2="HEADER2";
        String arg1 = "val1";
        String arg2 = "val2";
        String uri = "http://httpbin.org/get?arg1=" + arg1 + "&arg2=" + arg2;
        request.addRequestHeaders(new Header("Header1", header1));
        request.addRequestHeaders(new Header("Header2", header2));
        request.setMethod(RequestMethod.GET);
        request.request(uri);
        String response = request.getResponse();
        assertTrue(response.length() > 0);
        HttpBinResponse httpBinRespObj = gsonParser.fromJson(response, HttpBinResponse.class);
        assertEquals(httpBinRespObj.getArgs().get("arg1"), arg1);
        assertEquals(httpBinRespObj.getArgs().get("arg2"), arg2);
        assertTrue(httpBinRespObj.getOrigin().length() > 0);
        assertEquals(httpBinRespObj.getHeaders().get("Header1"), header1);
        assertEquals(httpBinRespObj.getHeaders().get("Header2"), header2);
    }
}
