/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import com.kanishka.net.commons.BasicHTTPRequestImpl;
import com.kanishka.net.commons.HTTPRequest;
import com.kanishka.net.model.RequestMethod;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import org.junit.After;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.runners.MockitoJUnitRunner;

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
        File eicarTestFile = new File("src/main/resources/testfiles/eicar.com.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
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
    public void testScanWithInvalidApiKey() throws APIKeyNotFoundException, UnsupportedEncodingException, UnauthorizedAccessException, FileNotFoundException, Exception {
        //when(httpRequestObject.request())
        File eicarTestFile = new File("src/main/resources/testfiles/eicar.com.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("invalid_api_key");
        //VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
    }
}
