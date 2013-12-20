/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import com.kanishka.net.commons.HTTPRequest;
import com.kanishka.net.model.HttpStatus;
import com.kanishka.net.model.RequestMethod;
import com.kanishka.net.model.Response;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.InvalidArguentsException;
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

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyList;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.when;

/**
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
        System.out.println("Test scanning a single file");
        final Response responseWrapper = (Response) PersistanceUtil.deSeralizeObject(new File("src/main/resources/persistedObjects/responseWrapperInScanFile.dat"));

        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.SUCCESSFUL);
                return responseWrapper;
            }
        });

        File eicarTestFile = new File("src/main/resources/testfiles/eicar.com.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
        assertNotNull(scanInformation);
        assertNotNull(scanInformation.getMd5());
        assertNotNull(scanInformation.getPermalink());
        assertNotNull(scanInformation.getResource());
        assertNotNull(scanInformation.getResponseCode());
        assertNotNull(scanInformation.getScanId());
        assertNotNull(scanInformation.getSha1());
        assertNotNull(scanInformation.getSha256());
        assertNotNull(scanInformation.getVerboseMessage());
    }

    @Test(expected = FileNotFoundException.class)
    public void testScanNotFoundFile() throws APIKeyNotFoundException, UnsupportedEncodingException, UnauthorizedAccessException, FileNotFoundException, Exception {
        System.out.println("Test scanning a single file when file does not exists");
        File eicarTestFile = new File("thisFileIsnotAvailable.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
    }

    @Test(expected = UnauthorizedAccessException.class)
    public void testScanFileWithInvalidApiKey() throws APIKeyNotFoundException, UnsupportedEncodingException, UnauthorizedAccessException, FileNotFoundException, Exception {
        System.out.println("Test scanning a single file when api key is invalid");
        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.FORBIDDEN);
                throw new IOException();
            }
        });

        File eicarTestFile = new File("src/main/resources/testfiles/eicar.com.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("invalid_api_key");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
    }

    @Test(expected = QuotaExceededException.class)
    public void testScanFileWhenQuotaExceed() throws Exception {
        System.out.println("Test scanning a single file when quota exceeded");
        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.API_LIMIT_EXCEEDED);
                throw new IOException();
            }
        });

        File eicarTestFile = new File("src/main/resources/testfiles/eicar.com.txt");
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo scanInformation = virusTotalRef.scanFile(eicarTestFile);
    }

    @Test(expected = InvalidArguentsException.class)
    public void testReScanFilesWhenInputResourcesIsNull() throws Exception {
        System.out.println("Test scanning files when provided resource array is null");
        String[] resources = null;
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
        virusTotalRef.reScanFiles(resources);
    }

    @Test
    public void testReScanFilesForTwoValidResources() throws Exception {
        System.out.println("Test re-scanning files for two valid resources");
        String[] resources = {"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"};

        final Response responseWrapper = (Response) PersistanceUtil.deSeralizeObject(new File("src/main/resources/persistedObjects/responseWrapperRescan2ValidFiles.dat"));

        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.SUCCESSFUL);
                return responseWrapper;
            }
        });
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo[] scanInfoArr = virusTotalRef.reScanFiles(resources);

        assertNotNull(scanInfoArr);
        assertTrue(scanInfoArr.length == 2);
        for (int i = 0; i < scanInfoArr.length; i++) {
            assertEquals(resources[i], scanInfoArr[i].getResource());
            assertNotNull(scanInfoArr[i].getPermalink());
            assertNotNull(scanInfoArr[i].getScanId());
        }
    }

    @Test(expected = QuotaExceededException.class)
    public void testReScanFilesWhenQuotaExceeded() throws Exception {
        System.out.println("Test scanning files when quota exceeded");

        String[] resources = {"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"};

        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.API_LIMIT_EXCEEDED);
                throw new IOException();
            }
        });

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo[] scanInfoArr = virusTotalRef.reScanFiles(resources);
    }

    @Test
    public void testScanReportForValidResource() throws Exception {
        System.out.println("Test scan report for valid resources");

        String resource = "5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152";
        final Response responseWrapper = (Response) PersistanceUtil.deSeralizeObject(new File("src/main/resources/persistedObjects/responseWrapperScanReportForValidResource.dat"));

        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.SUCCESSFUL);
                return responseWrapper;
            }
        });

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        FileScanReport fileScanReport = virusTotalRef.getScanReport(resource);

        assertNotNull(fileScanReport);
        assertTrue(fileScanReport.getScans().size() > 0);
        assertNotNull(fileScanReport.getScanId());
        assertNotNull(fileScanReport.getSha1());
        assertNotNull(fileScanReport.getResource());
        assertNotNull(fileScanReport.getPermalink());
        assertNotNull(fileScanReport.getTotal());
        assertNotNull(fileScanReport.getPositives());
        assertNotNull(fileScanReport.getPositives());
        assertNotNull(fileScanReport.getSha256());
        assertNotNull(fileScanReport.getMd5());

    }

    @Test(expected = QuotaExceededException.class)
    public void testScanReportForValidResourceWhenQuotaExceeded() throws Exception {
        System.out.println("Test scan report when quota exceeded");

        String resource = "5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152";
        final Response responseWrapper = (Response) PersistanceUtil.deSeralizeObject(new File("src/main/resources/persistedObjects/responseWrapperScanReportForValidResource.dat"));

        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.API_LIMIT_EXCEEDED);
                throw new IOException();
            }
        });

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        FileScanReport fileScanReport = virusTotalRef.getScanReport(resource);

        assertNotNull(fileScanReport);
        assertTrue(fileScanReport.getScans().size() > 0);
        assertNotNull(fileScanReport.getScanId());
        assertNotNull(fileScanReport.getSha1());
        assertNotNull(fileScanReport.getResource());
        assertNotNull(fileScanReport.getPermalink());
        assertNotNull(fileScanReport.getTotal());
        assertNotNull(fileScanReport.getPositives());
        assertNotNull(fileScanReport.getPositives());
        assertNotNull(fileScanReport.getSha256());
        assertNotNull(fileScanReport.getMd5());

    }

    @Test
    public void testGetScanReports() throws Exception {
        System.out.println("Test get scan reports for valid resources");

        String[] resources = {"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"};

        final Response responseWrapper = (Response) PersistanceUtil.deSeralizeObject(new File("src/main/resources/persistedObjects/responseWrapperScanReportsForValidResources.dat"));

        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.SUCCESSFUL);
                return responseWrapper;
            }
        });

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        FileScanReport[] fileScanReports = virusTotalRef.getScanReports(resources);

        assertNotNull(fileScanReports);
        assertTrue(fileScanReports.length == resources.length);
        for (int i = 0; i < fileScanReports.length; i++) {
            assertEquals(fileScanReports[i].getResource() , resources[i]);
            assertNotNull(fileScanReports[i].getResource());
            assertNotNull(fileScanReports[i].getScanId());
            assertNotNull(fileScanReports[i].getSha1());
            assertNotNull(fileScanReports[i].getPermalink());
            assertNotNull(fileScanReports[i].getTotal());
            assertNotNull(fileScanReports[i].getPositives());
            assertTrue(fileScanReports[i].getScans().size() > 0);
        }
    }

    @Test(expected = QuotaExceededException.class)
    public void testGetScanReportsWhenQuotaExceeded() throws Exception {
        System.out.println("Test get scan reports when quota exceeded");

        String[] resources = {"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"};

        final Response responseWrapper = (Response) PersistanceUtil.deSeralizeObject(new File("src/main/resources/persistedObjects/responseWrapperScanReportsForValidResources.dat"));

        when(httpRequestObject.request(anyString(), anyList(), anyList(), any(RequestMethod.class), anyList(), any(HttpStatus.class))).then(new Answer<Object>() {
            @Override
            public Object answer(InvocationOnMock invocationOnMock) throws Throwable {
                ((HttpStatus) invocationOnMock.getArguments()[5]).setStatusCode(VirustotalStatus.API_LIMIT_EXCEEDED);
                throw new IOException();
            }
        });

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("3d2a1046a17bb8d325403ae512e12f9467f159869817c834dac6aa7662235fb8");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        FileScanReport[] fileScanReports = virusTotalRef.getScanReports(resources);

    }

}
