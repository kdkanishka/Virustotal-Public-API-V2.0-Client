/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import com.kanishka.net.commons.HTTPRequest;
import com.kanishka.net.model.HttpStatus;
import com.kanishka.net.model.RequestMethod;
import com.kanishka.net.model.Response;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotal.util.PersistanceUtil;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.runners.MockitoJUnitRunner;
import org.mockito.stubbing.Answer;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

/**
 *
 * @author kanishka
 */
@RunWith(MockitoJUnitRunner.class)
public class VirustotalPublicV2ImplTest {
    
    @Mock
    private HTTPRequest httpRequestObject;
    
    @Before
    public void setUp() {
        MockitoAnnotations.initMocks(this);
    }

    @After
    public void tearDown() {
    }

    /**
     * Test of getConfigInstance method, of class VirusTotalConfig.
     */
    @Test
    public void testScanFile() throws APIKeyNotFoundException, UnsupportedEncodingException, UnauthorizedAccessException, Exception {
        final Response responseWrapper= (Response) PersistanceUtil.deSeralizeObject(new File("src/main/resources/persistedObjects/responseWrapperInScanFile.dat"));

        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus)invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.SUCCESSFUL);
                return responseWrapper;
            }
        }) ;

        File eicarTestFile = new File("src/main/resources/testfiles/eicar.com.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
        assertNotNull(scanInformation);
        assertNotNull(scanInformation.getMd5());
        assertNotNull(scanInformation.getPermalink());
        assertNotNull(scanInformation.getResource());
        assertNotNull(scanInformation.getResponse_code());
        assertNotNull(scanInformation.getScan_id());
        assertNotNull(scanInformation.getSha1());
        assertNotNull(scanInformation.getSha256());
        assertNotNull(scanInformation.getVerbose_msg());
    }

    @Test(expected = FileNotFoundException.class)
    public void testScanNotFoundFile() throws APIKeyNotFoundException, UnsupportedEncodingException, UnauthorizedAccessException, FileNotFoundException, Exception {
        File eicarTestFile = new File("thisFileIsnotAvailable.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
    }

    @Test(expected = UnauthorizedAccessException.class)
    public void testScanFileWithInvalidApiKey() throws APIKeyNotFoundException, UnsupportedEncodingException, UnauthorizedAccessException, FileNotFoundException, Exception {
        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus)invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.FORBIDDEN);
                throw new IOException();
            }
        }) ;

        File eicarTestFile = new File("src/main/resources/testfiles/eicar.com.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("invalid_api_key");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
    }

    @Test(expected = QuotaExceededException.class)
    public void testScanFileWhenQuotaExceed() throws Exception{
        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus)invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.API_LIMIT_EXCEEDED);
                throw new IOException();
            }
        }) ;

        File eicarTestFile = new File("src/main/resources/testfiles/eicar.com.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
    }
}
