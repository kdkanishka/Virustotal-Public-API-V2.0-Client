/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import com.kanishka.net.commons.HTTPRequest;
import com.kanishka.net.exception.RequestNotComplete;
import com.kanishka.net.model.HttpStatus;
import com.kanishka.net.model.RequestMethod;
import com.kanishka.net.model.Response;
import com.kanishka.virustotal.dto.DomainReport;
import com.kanishka.virustotal.dto.DomainResolution;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.GeneralResponse;
import com.kanishka.virustotal.dto.IPAddressReport;
import com.kanishka.virustotal.dto.IPAddressResolution;
import com.kanishka.virustotal.dto.Sample;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.dto.URL;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.InvalidArguentsException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.runners.MockitoJUnitRunner;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;

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
        String mockResponse = "{\"scan_id\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1408709699\", \"sha1\": \"3395856ce81f2b7382dee72602f798b642f14140\", \"resource\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\", \"response_code\": 1, \"sha256\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\", \"permalink\": \"https://www.virustotal.com/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/analysis/1408709699/\", \"md5\": \"44d88612fea8a8f36de82e1278abb02f\", \"verbose_msg\": \"Scan request successfully queued, come back later for the report\"}\n";
        final Response responseWrapper = new Response(HttpURLConnection.HTTP_OK,
                mockResponse, null);
        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenReturn
                (responseWrapper);

        File eicarTestFile = new File(this.getClass().getResource("/testfile").toURI());
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
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
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
        virusTotalRef.scanFile(eicarTestFile);
    }

    @Test(expected = UnauthorizedAccessException.class)
    public void testScanFileWithInvalidApiKey() throws APIKeyNotFoundException, UnsupportedEncodingException, UnauthorizedAccessException, FileNotFoundException, Exception {
        System.out.println("Test scanning a single file when api key is invalid");
        HttpStatus httpStatus = new HttpStatus(HttpURLConnection
                .HTTP_FORBIDDEN, "FORBIDDEN");

        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenThrow(new RequestNotComplete("", httpStatus));

        File eicarTestFile = new File(this.getClass().getResource("/testfile").toURI());
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("invalid_api_key");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        virusTotalRef.scanFile(eicarTestFile);
    }

    @Test(expected = QuotaExceededException.class)
    public void testScanFileWhenQuotaExceed() throws Exception {
        System.out.println("Test scanning a single file when quota exceeded");
        HttpStatus httpStatus = new HttpStatus(HttpURLConnection
                .HTTP_NO_CONTENT, "FORBIDDEN");

        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenThrow(new RequestNotComplete("", httpStatus));

        File eicarTestFile = new File(this.getClass().getResource("/testfile").toURI());
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        virusTotalRef.scanFile(eicarTestFile);
    }

    @Test(expected = InvalidArguentsException.class)
    public void testReScanFilesWhenInputResourcesIsNull() throws Exception {
        System.out.println("Test scanning files when provided resource array is null");
        String[] resources = null;
        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();
        virusTotalRef.reScanFiles(resources);
    }

    @Test
    public void testReScanFilesForTwoValidResources() throws Exception {
        System.out.println("Test re-scanning files for two valid resources");
        String[] resources = {"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"};

        String mockResponse = "[{\"permalink\": \"https://www.virustotal.com/file/5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152/analysis/1408713859/\", \"response_code\": 1, \"sha256\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152\", \"resource\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152\", \"scan_id\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152-1408713859\"}, {\"permalink\": \"https://www.virustotal.com/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/analysis/1408713859/\", \"response_code\": 1, \"sha256\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\", \"resource\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\", \"scan_id\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1408713859\"}]\n";
        final Response responseWrapper = new Response(200, mockResponse, null);

        when(httpRequestObject.request(anyString(), anyList(), anyList(),
                any(RequestMethod.class), anyList())).thenReturn
                (responseWrapper);

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        ScanInfo[] scanInfoArr = virusTotalRef.reScanFiles(resources);

        assertNotNull(scanInfoArr);
        assertTrue(scanInfoArr.length == 2);
        assertScanInfo(scanInfoArr[0], resources[0]);
        assertScanInfo(scanInfoArr[1], resources[1]);
    }

    private void assertScanInfo(ScanInfo scanInfo, String resource) {
        assertEquals(scanInfo.getResource(), resource);
        assertNotNull(scanInfo.getScanId());
        assertNotNull(scanInfo.getPermalink());
        assertTrue(scanInfo.getResponseCode() == 1);
    }

    @Test(expected = QuotaExceededException.class)
    public void testReScanFilesWhenQuotaExceeded() throws Exception {
        System.out.println("Test scanning files when quota exceeded");
        String[] resources = {"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"};
        HttpStatus httpStatus = new HttpStatus(HttpURLConnection
                .HTTP_NO_CONTENT, "FORBIDDEN");

        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenThrow(new RequestNotComplete("", httpStatus));

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        virusTotalRef.reScanFiles(resources);
    }

    @Test
    public void testScanReportForValidResource() throws Exception {
        System.out.println("Test scan report for valid resources");

        String resource = "5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152";

        String mockResponse = "{\"scans\": {\"Bkav\": {\"detected\": false, \"version\": \"1.3.0.4959\", \"result\": null, \"update\": \"20140821\"}, \"MicroWorld-eScan\": {\"detected\": false, \"version\": \"12.0.250.0\", \"result\": null, \"update\": \"20140822\"}, \"nProtect\": {\"detected\": false, \"version\": \"2014-08-22.01\", \"result\": null, \"update\": \"20140822\"}, \"CMC\": {\"detected\": false, \"version\": \"1.1.0.977\", \"result\": null, \"update\": \"20140822\"}, \"CAT-QuickHeal\": {\"detected\": false, \"version\": \"14.00\", \"result\": null, \"update\": \"20140822\"}, \"McAfee\": {\"detected\": false, \"version\": \"6.0.4.564\", \"result\": null, \"update\": \"20140822\"}, \"Malwarebytes\": {\"detected\": false, \"version\": \"1.75.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Zillya\": {\"detected\": false, \"version\": \"2.0.0.1898\", \"result\": null, \"update\": \"20140822\"}, \"SUPERAntiSpyware\": {\"detected\": false, \"version\": \"5.6.0.1032\", \"result\": null, \"update\": \"20140822\"}, \"K7AntiVirus\": {\"detected\": false, \"version\": \"9.183.13139\", \"result\": null, \"update\": \"20140822\"}, \"K7GW\": {\"detected\": false, \"version\": \"9.183.13139\", \"result\": null, \"update\": \"20140822\"}, \"TheHacker\": {\"detected\": false, \"version\": \"6.8.0.5.477\", \"result\": null, \"update\": \"20140817\"}, \"NANO-Antivirus\": {\"detected\": false, \"version\": \"0.28.2.61721\", \"result\": null, \"update\": \"20140822\"}, \"F-Prot\": {\"detected\": false, \"version\": \"4.7.1.166\", \"result\": null, \"update\": \"20140822\"}, \"Symantec\": {\"detected\": false, \"version\": \"20141.1.0.330\", \"result\": null, \"update\": \"20140822\"}, \"Norman\": {\"detected\": false, \"version\": \"7.04.04\", \"result\": null, \"update\": \"20140822\"}, \"TotalDefense\": {\"detected\": false, \"version\": \"37.0.11136\", \"result\": null, \"update\": \"20140822\"}, \"TrendMicro-HouseCall\": {\"detected\": false, \"version\": \"9.700.0.1001\", \"result\": null, \"update\": \"20140822\"}, \"Avast\": {\"detected\": false, \"version\": \"8.0.1489.320\", \"result\": null, \"update\": \"20140822\"}, \"ClamAV\": {\"detected\": false, \"version\": \"0.98.4.0\", \"result\": null, \"update\": \"20140821\"}, \"Kaspersky\": {\"detected\": false, \"version\": \"12.0.0.1225\", \"result\": null, \"update\": \"20140822\"}, \"BitDefender\": {\"detected\": false, \"version\": \"7.2\", \"result\": null, \"update\": \"20140822\"}, \"Agnitum\": {\"detected\": false, \"version\": \"5.5.1.3\", \"result\": null, \"update\": \"20140821\"}, \"ViRobot\": {\"detected\": false, \"version\": \"2011.4.7.4223\", \"result\": null, \"update\": \"20140822\"}, \"ByteHero\": {\"detected\": false, \"version\": \"1.0.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Tencent\": {\"detected\": false, \"version\": \"1.0.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Ad-Aware\": {\"detected\": false, \"version\": \"12.0.163.0\", \"result\": null, \"update\": \"20140822\"}, \"Sophos\": {\"detected\": false, \"version\": \"4.98.0\", \"result\": null, \"update\": \"20140822\"}, \"Comodo\": {\"detected\": false, \"version\": \"19277\", \"result\": null, \"update\": \"20140822\"}, \"F-Secure\": {\"detected\": false, \"version\": \"11.0.19100.45\", \"result\": null, \"update\": \"20140822\"}, \"DrWeb\": {\"detected\": false, \"version\": \"7.0.9.4080\", \"result\": null, \"update\": \"20140822\"}, \"VIPRE\": {\"detected\": false, \"version\": \"32442\", \"result\": null, \"update\": \"20140822\"}, \"AntiVir\": {\"detected\": false, \"version\": \"7.11.168.220\", \"result\": null, \"update\": \"20140822\"}, \"TrendMicro\": {\"detected\": false, \"version\": \"9.740.0.1012\", \"result\": null, \"update\": \"20140822\"}, \"McAfee-GW-Edition\": {\"detected\": false, \"version\": \"2013.2\", \"result\": null, \"update\": \"20140822\"}, \"Emsisoft\": {\"detected\": false, \"version\": \"3.0.0.600\", \"result\": null, \"update\": \"20140822\"}, \"Jiangmin\": {\"detected\": false, \"version\": \"16.0.100\", \"result\": null, \"update\": \"20140821\"}, \"Antiy-AVL\": {\"detected\": false, \"version\": \"1.0.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Kingsoft\": {\"detected\": false, \"version\": \"2013.4.9.267\", \"result\": null, \"update\": \"20140822\"}, \"Microsoft\": {\"detected\": false, \"version\": \"1.10904\", \"result\": null, \"update\": \"20140822\"}, \"AegisLab\": {\"detected\": false, \"version\": \"1.5\", \"result\": null, \"update\": \"20140822\"}, \"GData\": {\"detected\": false, \"version\": \"24\", \"result\": null, \"update\": \"20140822\"}, \"Commtouch\": {\"detected\": false, \"version\": \"5.4.1.7\", \"result\": null, \"update\": \"20140822\"}, \"AhnLab-V3\": {\"detected\": false, \"version\": \"2014.08.22.02\", \"result\": null, \"update\": \"20140822\"}, \"VBA32\": {\"detected\": false, \"version\": \"3.12.26.3\", \"result\": null, \"update\": \"20140822\"}, \"AVware\": {\"detected\": false, \"version\": \"1.5.0.16\", \"result\": null, \"update\": \"20140822\"}, \"Panda\": {\"detected\": false, \"version\": \"10.0.3.5\", \"result\": null, \"update\": \"20140822\"}, \"Zoner\": {\"detected\": false, \"version\": \"1.0\", \"result\": null, \"update\": \"20140821\"}, \"ESET-NOD32\": {\"detected\": false, \"version\": \"10297\", \"result\": null, \"update\": \"20140822\"}, \"Rising\": {\"detected\": false, \"version\": \"25.0.0.11\", \"result\": null, \"update\": \"20140822\"}, \"Ikarus\": {\"detected\": false, \"version\": \"T3.1.7.5.0\", \"result\": null, \"update\": \"20140822\"}, \"Fortinet\": {\"detected\": false, \"version\": \"5.1.152.0\", \"result\": null, \"update\": \"20140822\"}, \"AVG\": {\"detected\": false, \"version\": \"14.0.0.4007\", \"result\": null, \"update\": \"20140822\"}, \"Baidu-International\": {\"detected\": false, \"version\": \"3.5.1.41473\", \"result\": null, \"update\": \"20140822\"}, \"Qihoo-360\": {\"detected\": false, \"version\": \"1.0.0.1015\", \"result\": null, \"update\": \"20140822\"}}, \"scan_id\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152-1408713797\", \"sha1\": \"032e6b388be9be93e7d33f7c6229e3a62139188e\", \"resource\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152\", \"response_code\": 1, \"scan_date\": \"2014-08-22 13:23:17\", \"permalink\": \"https://www.virustotal.com/file/5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152/analysis/1408713797/\", \"verbose_msg\": \"Scan finished, scan information embedded in this object\", \"total\": 55, \"positives\": 0, \"sha256\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152\", \"md5\": \"b9bdd1e29345fee8ebc3c5650d397619\"}\n";
        final Response responseWrapper = new Response(200, mockResponse, null);
        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenReturn(responseWrapper);

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
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
        HttpStatus httpStatus = new HttpStatus(HttpURLConnection
                .HTTP_NO_CONTENT, "FORBIDDEN");

        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenThrow(new RequestNotComplete("", httpStatus));

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
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
        String mockResponse = "[{\"scans\": {\"Bkav\": {\"detected\": false, \"version\": \"1.3.0.4959\", \"result\": null, \"update\": \"20140821\"}, \"MicroWorld-eScan\": {\"detected\": false, \"version\": \"12.0.250.0\", \"result\": null, \"update\": \"20140822\"}, \"nProtect\": {\"detected\": false, \"version\": \"2014-08-22.01\", \"result\": null, \"update\": \"20140822\"}, \"CMC\": {\"detected\": false, \"version\": \"1.1.0.977\", \"result\": null, \"update\": \"20140822\"}, \"CAT-QuickHeal\": {\"detected\": false, \"version\": \"14.00\", \"result\": null, \"update\": \"20140822\"}, \"McAfee\": {\"detected\": false, \"version\": \"6.0.4.564\", \"result\": null, \"update\": \"20140822\"}, \"Malwarebytes\": {\"detected\": false, \"version\": \"1.75.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Zillya\": {\"detected\": false, \"version\": \"2.0.0.1898\", \"result\": null, \"update\": \"20140822\"}, \"SUPERAntiSpyware\": {\"detected\": false, \"version\": \"5.6.0.1032\", \"result\": null, \"update\": \"20140822\"}, \"K7AntiVirus\": {\"detected\": false, \"version\": \"9.183.13139\", \"result\": null, \"update\": \"20140822\"}, \"K7GW\": {\"detected\": false, \"version\": \"9.183.13139\", \"result\": null, \"update\": \"20140822\"}, \"TheHacker\": {\"detected\": false, \"version\": \"6.8.0.5.477\", \"result\": null, \"update\": \"20140817\"}, \"NANO-Antivirus\": {\"detected\": false, \"version\": \"0.28.2.61721\", \"result\": null, \"update\": \"20140822\"}, \"F-Prot\": {\"detected\": false, \"version\": \"4.7.1.166\", \"result\": null, \"update\": \"20140822\"}, \"Symantec\": {\"detected\": false, \"version\": \"20141.1.0.330\", \"result\": null, \"update\": \"20140822\"}, \"Norman\": {\"detected\": false, \"version\": \"7.04.04\", \"result\": null, \"update\": \"20140822\"}, \"TotalDefense\": {\"detected\": false, \"version\": \"37.0.11136\", \"result\": null, \"update\": \"20140822\"}, \"TrendMicro-HouseCall\": {\"detected\": false, \"version\": \"9.700.0.1001\", \"result\": null, \"update\": \"20140822\"}, \"Avast\": {\"detected\": false, \"version\": \"8.0.1489.320\", \"result\": null, \"update\": \"20140822\"}, \"ClamAV\": {\"detected\": false, \"version\": \"0.98.4.0\", \"result\": null, \"update\": \"20140821\"}, \"Kaspersky\": {\"detected\": false, \"version\": \"12.0.0.1225\", \"result\": null, \"update\": \"20140822\"}, \"BitDefender\": {\"detected\": false, \"version\": \"7.2\", \"result\": null, \"update\": \"20140822\"}, \"Agnitum\": {\"detected\": false, \"version\": \"5.5.1.3\", \"result\": null, \"update\": \"20140821\"}, \"ViRobot\": {\"detected\": false, \"version\": \"2011.4.7.4223\", \"result\": null, \"update\": \"20140822\"}, \"ByteHero\": {\"detected\": false, \"version\": \"1.0.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Tencent\": {\"detected\": false, \"version\": \"1.0.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Ad-Aware\": {\"detected\": false, \"version\": \"12.0.163.0\", \"result\": null, \"update\": \"20140822\"}, \"Sophos\": {\"detected\": false, \"version\": \"4.98.0\", \"result\": null, \"update\": \"20140822\"}, \"Comodo\": {\"detected\": false, \"version\": \"19277\", \"result\": null, \"update\": \"20140822\"}, \"F-Secure\": {\"detected\": false, \"version\": \"11.0.19100.45\", \"result\": null, \"update\": \"20140822\"}, \"DrWeb\": {\"detected\": false, \"version\": \"7.0.9.4080\", \"result\": null, \"update\": \"20140822\"}, \"VIPRE\": {\"detected\": false, \"version\": \"32442\", \"result\": null, \"update\": \"20140822\"}, \"AntiVir\": {\"detected\": false, \"version\": \"7.11.168.220\", \"result\": null, \"update\": \"20140822\"}, \"TrendMicro\": {\"detected\": false, \"version\": \"9.740.0.1012\", \"result\": null, \"update\": \"20140822\"}, \"McAfee-GW-Edition\": {\"detected\": false, \"version\": \"2013.2\", \"result\": null, \"update\": \"20140822\"}, \"Emsisoft\": {\"detected\": false, \"version\": \"3.0.0.600\", \"result\": null, \"update\": \"20140822\"}, \"Jiangmin\": {\"detected\": false, \"version\": \"16.0.100\", \"result\": null, \"update\": \"20140821\"}, \"Antiy-AVL\": {\"detected\": false, \"version\": \"1.0.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Kingsoft\": {\"detected\": false, \"version\": \"2013.4.9.267\", \"result\": null, \"update\": \"20140822\"}, \"Microsoft\": {\"detected\": false, \"version\": \"1.10904\", \"result\": null, \"update\": \"20140822\"}, \"AegisLab\": {\"detected\": false, \"version\": \"1.5\", \"result\": null, \"update\": \"20140822\"}, \"GData\": {\"detected\": false, \"version\": \"24\", \"result\": null, \"update\": \"20140822\"}, \"Commtouch\": {\"detected\": false, \"version\": \"5.4.1.7\", \"result\": null, \"update\": \"20140822\"}, \"AhnLab-V3\": {\"detected\": false, \"version\": \"2014.08.22.02\", \"result\": null, \"update\": \"20140822\"}, \"VBA32\": {\"detected\": false, \"version\": \"3.12.26.3\", \"result\": null, \"update\": \"20140822\"}, \"AVware\": {\"detected\": false, \"version\": \"1.5.0.16\", \"result\": null, \"update\": \"20140822\"}, \"Panda\": {\"detected\": false, \"version\": \"10.0.3.5\", \"result\": null, \"update\": \"20140822\"}, \"Zoner\": {\"detected\": false, \"version\": \"1.0\", \"result\": null, \"update\": \"20140821\"}, \"ESET-NOD32\": {\"detected\": false, \"version\": \"10297\", \"result\": null, \"update\": \"20140822\"}, \"Rising\": {\"detected\": false, \"version\": \"25.0.0.11\", \"result\": null, \"update\": \"20140822\"}, \"Ikarus\": {\"detected\": false, \"version\": \"T3.1.7.5.0\", \"result\": null, \"update\": \"20140822\"}, \"Fortinet\": {\"detected\": false, \"version\": \"5.1.152.0\", \"result\": null, \"update\": \"20140822\"}, \"AVG\": {\"detected\": false, \"version\": \"14.0.0.4007\", \"result\": null, \"update\": \"20140822\"}, \"Baidu-International\": {\"detected\": false, \"version\": \"3.5.1.41473\", \"result\": null, \"update\": \"20140822\"}, \"Qihoo-360\": {\"detected\": false, \"version\": \"1.0.0.1015\", \"result\": null, \"update\": \"20140822\"}}, \"scan_id\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152-1408713797\", \"sha1\": \"032e6b388be9be93e7d33f7c6229e3a62139188e\", \"resource\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152\", \"response_code\": 1, \"scan_date\": \"2014-08-22 13:23:17\", \"permalink\": \"https://www.virustotal.com/file/5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152/analysis/1408713797/\", \"verbose_msg\": \"Scan finished, scan information embedded in this object\", \"total\": 55, \"positives\": 0, \"sha256\": \"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152\", \"md5\": \"b9bdd1e29345fee8ebc3c5650d397619\"}, {\"scans\": {\"Bkav\": {\"detected\": true, \"version\": \"1.3.0.4959\", \"result\": \"DOS.EiracA.Trojan\", \"update\": \"20140821\"}, \"MicroWorld-eScan\": {\"detected\": true, \"version\": \"12.0.250.0\", \"result\": \"EICAR-Test-File\", \"update\": \"20140822\"}, \"nProtect\": {\"detected\": true, \"version\": \"2014-08-22.01\", \"result\": \"EICAR-Test-File\", \"update\": \"20140822\"}, \"CMC\": {\"detected\": true, \"version\": \"1.1.0.977\", \"result\": \"Eicar.test.file\", \"update\": \"20140822\"}, \"CAT-QuickHeal\": {\"detected\": true, \"version\": \"14.00\", \"result\": \"EICAR.TestFile\", \"update\": \"20140822\"}, \"McAfee\": {\"detected\": true, \"version\": \"6.0.4.564\", \"result\": \"EICAR test file\", \"update\": \"20140822\"}, \"Malwarebytes\": {\"detected\": false, \"version\": \"1.75.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Zillya\": {\"detected\": true, \"version\": \"2.0.0.1898\", \"result\": \"EICAR.TestFile\", \"update\": \"20140822\"}, \"SUPERAntiSpyware\": {\"detected\": true, \"version\": \"5.6.0.1032\", \"result\": \"NotAThreat.EICAR[TestFile]\", \"update\": \"20140822\"}, \"K7AntiVirus\": {\"detected\": true, \"version\": \"9.183.13139\", \"result\": \"EICAR_Test_File\", \"update\": \"20140822\"}, \"K7GW\": {\"detected\": true, \"version\": \"9.183.13139\", \"result\": \"EICAR_Test_File\", \"update\": \"20140822\"}, \"TheHacker\": {\"detected\": true, \"version\": \"6.8.0.5.477\", \"result\": \"EICAR_Test_File\", \"update\": \"20140817\"}, \"NANO-Antivirus\": {\"detected\": true, \"version\": \"0.28.2.61721\", \"result\": \"Marker.Dos.EICAR-Test-File.dyb\", \"update\": \"20140822\"}, \"F-Prot\": {\"detected\": true, \"version\": \"4.7.1.166\", \"result\": \"EICAR_Test_File\", \"update\": \"20140822\"}, \"Symantec\": {\"detected\": true, \"version\": \"20141.1.0.330\", \"result\": \"EICAR Test String\", \"update\": \"20140822\"}, \"Norman\": {\"detected\": false, \"version\": \"7.04.04\", \"result\": null, \"update\": \"20140822\"}, \"TotalDefense\": {\"detected\": true, \"version\": \"37.0.11136\", \"result\": \"the EICAR test string\", \"update\": \"20140822\"}, \"TrendMicro-HouseCall\": {\"detected\": true, \"version\": \"9.700.0.1001\", \"result\": \"Eicar_test_file\", \"update\": \"20140822\"}, \"Avast\": {\"detected\": true, \"version\": \"8.0.1489.320\", \"result\": \"EICAR Test-NOT virus!!!\", \"update\": \"20140822\"}, \"ClamAV\": {\"detected\": true, \"version\": \"0.98.4.0\", \"result\": \"Eicar-Test-Signature\", \"update\": \"20140821\"}, \"Kaspersky\": {\"detected\": true, \"version\": \"12.0.0.1225\", \"result\": \"EICAR-Test-File\", \"update\": \"20140822\"}, \"BitDefender\": {\"detected\": true, \"version\": \"7.2\", \"result\": \"EICAR-Test-File (not a virus)\", \"update\": \"20140822\"}, \"Agnitum\": {\"detected\": true, \"version\": \"5.5.1.3\", \"result\": \"EICAR_test_file\", \"update\": \"20140821\"}, \"ViRobot\": {\"detected\": true, \"version\": \"2011.4.7.4223\", \"result\": \"EICAR-test\", \"update\": \"20140822\"}, \"ByteHero\": {\"detected\": false, \"version\": \"1.0.0.1\", \"result\": null, \"update\": \"20140822\"}, \"Tencent\": {\"detected\": true, \"version\": \"1.0.0.1\", \"result\": \"EICAR.TEST.NOT-A-VIRUS\", \"update\": \"20140822\"}, \"Ad-Aware\": {\"detected\": true, \"version\": \"12.0.163.0\", \"result\": \"EICAR-Test-File (not a virus)\", \"update\": \"20140822\"}, \"Sophos\": {\"detected\": true, \"version\": \"4.98.0\", \"result\": \"EICAR-AV-Test\", \"update\": \"20140822\"}, \"Comodo\": {\"detected\": true, \"version\": \"19277\", \"result\": \"Application.EICAR-Test-File\", \"update\": \"20140822\"}, \"F-Secure\": {\"detected\": true, \"version\": \"11.0.19100.45\", \"result\": \"EICAR_Test_File\", \"update\": \"20140822\"}, \"DrWeb\": {\"detected\": true, \"version\": \"7.0.9.4080\", \"result\": \"EICAR Test File (NOT a Virus!)\", \"update\": \"20140822\"}, \"VIPRE\": {\"detected\": true, \"version\": \"32442\", \"result\": \"EICAR (v)\", \"update\": \"20140822\"}, \"AntiVir\": {\"detected\": true, \"version\": \"7.11.168.220\", \"result\": \"Eicar-Test-Signature\", \"update\": \"20140822\"}, \"TrendMicro\": {\"detected\": true, \"version\": \"9.740.0.1012\", \"result\": \"Eicar_test_file\", \"update\": \"20140822\"}, \"McAfee-GW-Edition\": {\"detected\": false, \"version\": \"2013.2\", \"result\": null, \"update\": \"20140822\"}, \"Emsisoft\": {\"detected\": true, \"version\": \"3.0.0.600\", \"result\": \"EICAR-Test-File (not a virus) (B)\", \"update\": \"20140822\"}, \"Jiangmin\": {\"detected\": true, \"version\": \"16.0.100\", \"result\": \"EICAR-Test-File\", \"update\": \"20140821\"}, \"Antiy-AVL\": {\"detected\": true, \"version\": \"1.0.0.1\", \"result\": \"Test[:not-a-virus]/Win32.EICAR\", \"update\": \"20140822\"}, \"Kingsoft\": {\"detected\": true, \"version\": \"2013.4.9.267\", \"result\": \"Test.eicar.aa\", \"update\": \"20140822\"}, \"Microsoft\": {\"detected\": true, \"version\": \"1.10904\", \"result\": \"Virus:DOS/EICAR_Test_File\", \"update\": \"20140822\"}, \"AegisLab\": {\"detected\": false, \"version\": \"1.5\", \"result\": null, \"update\": \"20140822\"}, \"GData\": {\"detected\": true, \"version\": \"24\", \"result\": \"EICAR-Test-File (not a virus)\", \"update\": \"20140822\"}, \"Commtouch\": {\"detected\": true, \"version\": \"5.4.1.7\", \"result\": \"EICAR_Test_File\", \"update\": \"20140822\"}, \"AhnLab-V3\": {\"detected\": true, \"version\": \"2014.08.22.02\", \"result\": \"EICAR_Test_File\", \"update\": \"20140822\"}, \"VBA32\": {\"detected\": true, \"version\": \"3.12.26.3\", \"result\": \"EICAR-Test-File\", \"update\": \"20140822\"}, \"AVware\": {\"detected\": true, \"version\": \"1.5.0.16\", \"result\": \"EICAR (v)\", \"update\": \"20140822\"}, \"Panda\": {\"detected\": true, \"version\": \"10.0.3.5\", \"result\": \"EICAR-AV-TEST-FILE\", \"update\": \"20140822\"}, \"Zoner\": {\"detected\": true, \"version\": \"1.0\", \"result\": \"EICAR.Test.File-NoVirus\", \"update\": \"20140821\"}, \"ESET-NOD32\": {\"detected\": true, \"version\": \"10297\", \"result\": \"Eicar test file\", \"update\": \"20140822\"}, \"Rising\": {\"detected\": true, \"version\": \"25.0.0.11\", \"result\": \"NORMAL:EICAR-Test-File!84776\", \"update\": \"20140822\"}, \"Ikarus\": {\"detected\": true, \"version\": \"T3.1.7.5.0\", \"result\": \"EICAR-ANTIVIRUS-TESTFILE\", \"update\": \"20140822\"}, \"Fortinet\": {\"detected\": true, \"version\": \"5.1.152.0\", \"result\": \"EICAR_TEST_FILE\", \"update\": \"20140822\"}, \"AVG\": {\"detected\": true, \"version\": \"14.0.0.4007\", \"result\": \"EICAR_Test\", \"update\": \"20140822\"}, \"Baidu-International\": {\"detected\": true, \"version\": \"3.5.1.41473\", \"result\": \"EICAR.Test.File\", \"update\": \"20140822\"}, \"Qihoo-360\": {\"detected\": true, \"version\": \"1.0.0.1015\", \"result\": \"Trojan.Generic\", \"update\": \"20140822\"}}, \"scan_id\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f-1408713798\", \"sha1\": \"3395856ce81f2b7382dee72602f798b642f14140\", \"resource\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\", \"response_code\": 1, \"scan_date\": \"2014-08-22 13:23:18\", \"permalink\": \"https://www.virustotal.com/file/275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f/analysis/1408713798/\", \"verbose_msg\": \"Scan finished, scan information embedded in this object\", \"total\": 55, \"positives\": 50, \"sha256\": \"275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\", \"md5\": \"44d88612fea8a8f36de82e1278abb02f\"}]\n";
        final Response responseWrapper = new Response(200, mockResponse, null);
        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenReturn(responseWrapper);

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        FileScanReport[] fileScanReports = virusTotalRef.getScanReports(resources);

        assertNotNull(fileScanReports);
        assertTrue(fileScanReports.length == resources.length);
        assertFileScanReport(fileScanReports[0], resources[0]);
        assertFileScanReport(fileScanReports[1], resources[1]);
    }

    @Test(expected = QuotaExceededException.class)
    public void testGetScanReportsWhenQuotaExceeded() throws Exception {
        System.out.println("Test get scan reports when quota exceeded");
        String[] resources = {"5a01e158c7f7143086187982770aff1e799d95077a380353b4b1d6dfb6efc152", "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"};
        HttpStatus httpStatus = new HttpStatus(HttpURLConnection
                .HTTP_NO_CONTENT, "FORBIDDEN");

        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenThrow(new RequestNotComplete("", httpStatus));

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        virusTotalRef.getScanReports(resources);
    }

    @Test
    public void testGetDomainReports() throws Exception {
        String mockResponse = "{\"undetected_downloaded_samples\": [{\"date\": \"2013-07-23 17:55:42\", \"positives\": 0, \"total\": 47, \"sha256\": \"abb543e1f695c11124176c6c6fc78abbc237cca496d2431867e541ac71c65853\"}, {\"date\": \"2013-07-23 15:52:56\", \"positives\": 0, \"total\": 42, \"sha256\": \"f66843c6015b184a57a1d90db293124e8e82dca845356d29ae7e4bc2408eda57\"}], \"response_code\": 1, \"detected_urls\": [{\"url\": \"http://www.ntt62.com/paypal.com.au.ftp6/\", \"positives\": 7, \"total\": 39, \"scan_date\": \"2013-07-23 17:54:13\"}], \"resolutions\": [{\"last_resolved\": \"2013-07-23 00:00:00\", \"ip_address\": \"69.195.124.58\"}], \"verbose_msg\": \"Domain found in dataset\"}\n";
        final Response responseWrapper = new Response(200, mockResponse, null);
        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenReturn(responseWrapper);

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        DomainReport domainReport = virusTotalRef.getDomainReport("www.ntt62.com");

        assertEquals(domainReport.getResponseCode(), 1);
        assertEquals(domainReport.getVerboseMessage(), "Domain found in dataset");
        Sample[] sample = domainReport.getUndetectedDownloadedSamples();
        assertSample(sample[0]);
        assertSample(sample[1]);
        DomainResolution[] domainResolutions = domainReport.getResolutions();
        assertDomainResolution(domainResolutions[0]);
        URL[] detectedUrls = domainReport.getDetectedUrls();
        assertUrl(detectedUrls[0]);
    }

    @Test
    public void testGetIPAddressReport() throws Exception {
        String mockResponse = "{\"undetected_downloaded_samples\": [{\"date\": \"2014-07-18 21:13:59\", \"positives\": 0, \"total\": 51, \"sha256\": \"a90f6297d836459421d3ee5d243bec5d35e02db13b0a60bdca0e414358cd1898\"}, {\"date\": \"2014-06-27 22:47:34\", \"positives\": 0, \"total\": 54, \"sha256\": \"90463ceddc29691bfcd02ec645e123e85283cdadcf9160df19dcb023318798cf\"}, {\"date\": \"2014-06-11 15:02:35\", \"positives\": 0, \"total\": 47, \"sha256\": \"9f3bdae9e79831f32ebcd9950db9aef385db34e2f173203369aa374a0256d269\"}, {\"date\": \"2014-04-08 23:08:36\", \"positives\": 0, \"total\": 51, \"sha256\": \"109c6d8bb96c610ba3f9fa0c43a8fb053a70a343875013d418240d927d80a476\"}, {\"date\": \"2014-03-14 23:41:58\", \"positives\": 0, \"total\": 50, \"sha256\": \"ca5e28e94e67ded732b413e975d375964e9d79c900fd910a62956970d102ea57\"}, {\"date\": \"2013-12-10 22:12:17\", \"positives\": 0, \"total\": 49, \"sha256\": \"fa58f4ab5bc71763e3cd6c1a403bc7e3ad339322efa1a3a3cd451b11d82ebfcd\"}, {\"date\": \"2013-12-10 22:12:15\", \"positives\": 0, \"total\": 49, \"sha256\": \"3e57886ea67fad3e6a6039ad15c9c44a71127f0c5657d331e70cb7b6ae468e18\"}, {\"date\": \"2013-12-10 22:12:08\", \"positives\": 0, \"total\": 49, \"sha256\": \"d98e4c5e74d10dbb6183a816888d28ccb38b031bb432ff3d56cc9b0bbb34005c\"}, {\"date\": \"2013-12-10 22:12:02\", \"positives\": 0, \"total\": 49, \"sha256\": \"125243cb7750a991b25ef901eb65729808522ad0afaddb959d2546275fbe7f87\"}, {\"date\": \"2013-08-25 01:50:17\", \"positives\": 0, \"total\": 44, \"sha256\": \"7facc7b471604b0801acd2fda474fe806a79636dfbc7776b4740ba6e790bb86a\"}, {\"date\": \"2013-08-03 10:25:10\", \"positives\": 0, \"total\": 47, \"sha256\": \"bcbe1a7da83bd5c521935b537da70f3636cd0416fa882db32cedcd969ff13db2\"}, {\"date\": \"2013-07-23 17:55:43\", \"positives\": 0, \"total\": 47, \"sha256\": \"abb543e1f695c11124176c6c6fc78abbc237cca496d2431867e541ac71c65853\"}, {\"date\": \"2013-07-23 16:31:50\", \"positives\": 0, \"total\": 47, \"sha256\": \"77b6fe6a22a617d53faf43226fd81d01657028c9d602d7f8ccf0eee3d741c002\"}, {\"date\": \"2013-07-23 15:52:56\", \"positives\": 0, \"total\": 42, \"sha256\": \"f66843c6015b184a57a1d90db293124e8e82dca845356d29ae7e4bc2408eda57\"}], \"detected_downloaded_samples\": [{\"date\": \"2014-05-22 11:29:20\", \"positives\": 2, \"total\": 47, \"sha256\": \"e9d221432bc8f71517be5a3f35f8387ca0a5da4ef9f225d07720e02e930882d3\"}, {\"date\": \"2013-08-13 07:06:11\", \"positives\": 5, \"total\": 44, \"sha256\": \"4f9391cab73d5bde3a014b8be8804f9f23cc0b4ce31927d560ea4f635e47a8e5\"}], \"response_code\": 1, \"detected_urls\": [{\"url\": \"http://cobcf.org/wp-content/church_uploads/dk.php\", \"positives\": 1, \"total\": 58, \"scan_date\": \"2014-08-04 07:15:09\"}, {\"url\": \"http://www.bagpipestand.com/\", \"positives\": 1, \"total\": 53, \"scan_date\": \"2014-07-02 13:15:20\"}, {\"url\": \"http://www.e-howtogetridofdandruff.com/\", \"positives\": 1, \"total\": 53, \"scan_date\": \"2014-07-02 09:40:07\"}, {\"url\": \"http://www.80diapers.com/\", \"positives\": 1, \"total\": 52, \"scan_date\": \"2014-06-23 06:09:28\"}, {\"url\": \"http://www.hijosyalimentacion.com/\", \"positives\": 1, \"total\": 52, \"scan_date\": \"2014-06-09 08:16:05\"}, {\"url\": \"http://dubaiphotos.cc/\", \"positives\": 2, \"total\": 52, \"scan_date\": \"2014-05-21 12:00:33\"}, {\"url\": \"http://kitzig.com.sg/\", \"positives\": 1, \"total\": 51, \"scan_date\": \"2014-04-23 18:38:27\"}, {\"url\": \"http://ashlandcomedy.com/\", \"positives\": 3, \"total\": 51, \"scan_date\": \"2014-03-23 02:14:15\"}, {\"url\": \"http://telechargement-fr.us/Andemu_4.4_Windows.zip\", \"positives\": 1, \"total\": 53, \"scan_date\": \"2014-02-15 16:50:19\"}, {\"url\": \"http://chezlysa.com/\", \"positives\": 1, \"total\": 53, \"scan_date\": \"2014-02-12 04:45:51\"}, {\"url\": \"http://telechargement-fr.us/\", \"positives\": 1, \"total\": 51, \"scan_date\": \"2014-01-02 15:05:45\"}, {\"url\": \"http://mahamegha.org/\", \"positives\": 1, \"total\": 51, \"scan_date\": \"2013-11-28 18:58:58\"}, {\"url\": \"http://www.itunesgiftcard4u.com/\", \"positives\": 3, \"total\": 51, \"scan_date\": \"2013-11-20 21:09:55\"}, {\"url\": \"http://bonotv.net/?p=1097\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-12 08:23:01\"}, {\"url\": \"http://bonotv.net/?cat=14\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-10 16:39:00\"}, {\"url\": \"http://bonotv.net/category/hoshin-shog/\", \"positives\": 5, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:59\"}, {\"url\": \"http://bonotv.net/north-face-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80/\", \"positives\": 5, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:59\"}, {\"url\": \"http://bonotv.net/my-way-2011-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 5, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:59\"}, {\"url\": \"http://bonotv.net/?p=1100\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:59\"}, {\"url\": \"http://bonotv.net/?p=1280\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:59\"}, {\"url\": \"http://bonotv.net/?p=1111\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:59\"}, {\"url\": \"http://bonotv.net/?paged=8\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:59\"}, {\"url\": \"http://bonotv.net/pacific-rim-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:59\"}, {\"url\": \"http://bonotv.net/?paged=2\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:58\"}, {\"url\": \"http://bonotv.net/paranorman/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:58\"}, {\"url\": \"http://bonotv.net/thats-my-boy-2012-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:58\"}, {\"url\": \"http://bonotv.net/the-thieves/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:58\"}, {\"url\": \"http://bonotv.net/universal-soldier/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:58\"}, {\"url\": \"http://bonotv.net/the-white-masai/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-10 16:38:58\"}, {\"url\": \"http://bonotv.net/?cat=9\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-10 11:41:50\"}, {\"url\": \"http://bonotv.net/?p=1029\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-10 16:17:01\"}, {\"url\": \"http://bonotv.net/?page_id=4\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-11-10 12:38:09\"}, {\"url\": \"http://mp3sell.com/download/lagu/tegar/\", \"positives\": 1, \"total\": 50, \"scan_date\": \"2013-11-09 05:39:26\"}, {\"url\": \"http://bonotv.net/evil-dead-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-05 15:01:05\"}, {\"url\": \"http://bonotv.net/fright-night-2-new-blood-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-05 08:13:02\"}, {\"url\": \"http://bonotv.net/%D1%88%D3%A9%D0%BD%D3%A9-%D0%B4%D1%83%D0%BD%D0%B4%D1%8B%D0%BD-%D1%8F%D1%80%D0%B8%D0%B0-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-05 08:12:53\"}, {\"url\": \"http://bonotv.net/%D1%8D%D0%BC%D0%BE%D1%86%D0%B8-%D1%8D%D1%85%D0%BD%D1%8D%D1%80%D2%AF%D2%AF%D0%B4%D0%B8%D0%B9%D0%BD-%D0%B1%D0%B0%D0%B7%D0%B0%D0%B0/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-05 08:12:48\"}, {\"url\": \"http://bonotv.net/the-bling-ring-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-05 08:12:45\"}, {\"url\": \"http://bonotv.net/the-horde-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-05 08:12:44\"}, {\"url\": \"http://bonotv.net/category/%D0%B0%D0%B9%D0%BC%D1%88%D0%B3%D0%B8%D0%B9%D0%BD/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-05 08:12:31\"}, {\"url\": \"http://bonotv.net/the-lone-ranger-2013-hd-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-11-05 08:12:27\"}, {\"url\": \"http://bonotv.net/%D0%B1%D1%83%D1%80%D1%83%D1%83-%D1%8D%D1%80%D0%B3%D1%8D%D0%BB%D1%82-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-10-29 22:38:54\"}, {\"url\": \"http://bonotv.net/deranged-2012-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-10-29 22:39:02\"}, {\"url\": \"http://bonotv.net/spring-breakers-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-10-29 22:38:53\"}, {\"url\": \"http://bonotv.net/category/%D1%85%D0%B0%D0%B9%D1%80-%D0%B4%D1%83%D1%80%D0%BB%D0%B0%D0%BB/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-10-29 22:38:51\"}, {\"url\": \"http://bonotv.net/barbie-princess-popstar/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-10-29 22:38:46\"}, {\"url\": \"http://bonotv.net/%D0%B0%D0%BC%D1%8C%D0%B4%D1%80%D0%B0%D0%BB-%D1%82%D3%A9%D1%81%D3%A9%D0%BB-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 5, \"total\": 50, \"scan_date\": \"2013-10-30 03:25:07\"}, {\"url\": \"http://bonotv.net/brigada/\", \"positives\": 5, \"total\": 50, \"scan_date\": \"2013-10-30 03:25:07\"}, {\"url\": \"http://bonotv.net/the-conjuring-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 5, \"total\": 50, \"scan_date\": \"2013-10-30 03:25:06\"}, {\"url\": \"http://bonotv.net/%D0%B4%D1%8D%D0%BB%D1%85%D0%B8%D0%B9%D0%B4-%D0%B4%D1%83%D1%80%D0%BB%D0%B0%D1%81%D0%B0%D0%BD-%D1%81%D0%B0%D1%80-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-10-30 02:56:19\"}, {\"url\": \"http://bonotv.net/%D1%85%D3%A9%D1%85-%D1%82%D0%BE%D0%BB%D0%B1%D0%BE%D1%82-%D1%85%D2%AF%D0%BC%D2%AF%D2%AF%D1%81-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-10-30 02:56:19\"}, {\"url\": \"http://bonotv.net/%D1%82%D1%8D%D0%BD%D0%B3%D1%8D%D1%80%D0%B8%D0%B9%D0%BD-%D0%BF%D1%80%D0%BE%D0%B4%D1%8E%D1%81%D0%B5%D1%80-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-10-30 02:56:18\"}, {\"url\": \"http://bonotv.net/the-dark-knight-rises/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-10-30 01:16:40\"}, {\"url\": \"http://bonotv.net/kick-ass-2-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-10-30 01:16:40\"}, {\"url\": \"http://bonotv.net/%D1%85%D0%BE%D0%B2%D1%87-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 4, \"total\": 50, \"scan_date\": \"2013-10-30 01:16:40\"}, {\"url\": \"http://bonotv.net/oblivion-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-10-29 22:38:13\"}, {\"url\": \"http://bonotv.net/%D2%AF%D0%BB%D0%B3%D1%8D%D1%80%D0%B8%D0%B9%D0%BD-%D1%85%D0%B0%D0%B9%D1%80-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 3, \"total\": 50, \"scan_date\": \"2013-10-29 23:21:58\"}, {\"url\": \"http://bonotv.net/the-concubine/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 19:09:12\"}, {\"url\": \"http://bonotv.net/argo/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 20:19:05\"}, {\"url\": \"http://bonotv.net/now-you-see-me-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 20:19:04\"}, {\"url\": \"http://bonotv.net/%D1%81%D0%B0%D0%B9%D0%BD-%D0%BC%D1%83%D1%83-%D1%85%D1%8D%D1%80%D1%86%D0%B3%D0%B8%D0%B9-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 20:19:04\"}, {\"url\": \"http://bonotv.net/uye-girisi/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 20:19:04\"}, {\"url\": \"http://bonotv.net/white-house-down-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 19:09:12\"}, {\"url\": \"http://bonotv.net/r-i-p-d-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 19:09:12\"}, {\"url\": \"http://bonotv.net/%D0%B4%D1%8D%D0%BB%D1%85%D0%B8%D0%B9%D0%BD-%D0%B4%D0%B0%D0%B9%D0%BD-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 19:09:11\"}, {\"url\": \"http://bonotv.net/%D0%BF%D0%BE%D0%BC%D0%BE%D0%B3%D0%B8%D1%82%D0%B5-%D0%BD%D0%B0%D0%BC-3-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 3, \"total\": 49, \"scan_date\": \"2013-10-25 19:09:10\"}, {\"url\": \"http://bonotv.net/road-trip-2000-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB/\", \"positives\": 3, \"total\": 47, \"scan_date\": \"2013-10-23 16:22:11\"}, {\"url\": \"http://bonotv.net/\", \"positives\": 1, \"total\": 47, \"scan_date\": \"2013-10-22 15:16:40\"}, {\"url\": \"http://bonotv.net/%D2%AF%D0%BD%D1%8D%D0%BD%D1%8D%D1%8D%D1%81-%D1%85%D0%BE%D0%BB-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 1, \"total\": 47, \"scan_date\": \"2013-10-22 14:37:02\"}, {\"url\": \"http://www.brightlightsrun.com/about/\", \"positives\": 1, \"total\": 39, \"scan_date\": \"2013-09-30 20:46:53\"}, {\"url\": \"http://3vrealty.com/\", \"positives\": 1, \"total\": 39, \"scan_date\": \"2013-09-18 21:20:18\"}, {\"url\": \"http://bayviewdentalny.com/\", \"positives\": 1, \"total\": 39, \"scan_date\": \"2013-09-17 03:20:31\"}, {\"url\": \"http://www.mongolbox.com/the-thieves\", \"positives\": 3, \"total\": 39, \"scan_date\": \"2013-09-14 06:17:29\"}, {\"url\": \"http://www.mongolbox.com/the-thieves/\", \"positives\": 2, \"total\": 39, \"scan_date\": \"2013-09-13 13:02:28\"}, {\"url\": \"http://itunesgiftcard4u.com/login\", \"positives\": 4, \"total\": 39, \"scan_date\": \"2013-09-12 12:02:08\"}, {\"url\": \"http://www.mongolbox.com/2359--\", \"positives\": 3, \"total\": 39, \"scan_date\": \"2013-09-12 04:16:05\"}, {\"url\": \"http://www.mongolbox.com/%D1%81%D0%B0%D1%8F-%D0%B4%D0%BE%D0%BB%D0%BB%D0%B0%D1%80%D1%8B%D0%BD-%D0%BE%D0%BB%D0%B7-%D0%BC%D1%83%D1%81%D0%BA\", \"positives\": 2, \"total\": 38, \"scan_date\": \"2013-09-09 14:36:04\"}, {\"url\": \"http://www.mongolbox.com/%D0%B1%D1%83%D1%80%D1%85%D0%B0%D0%BD-%D3%A9%D1%80%D1%88%D3%A9%D3%A9%D0%B3-%D0%BC%D1%83%D1%81%D0%BA\", \"positives\": 2, \"total\": 38, \"scan_date\": \"2013-09-09 14:36:04\"}, {\"url\": \"http://www.mongolbox.com/2359-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80/\", \"positives\": 2, \"total\": 38, \"scan_date\": \"2013-09-06 01:19:33\"}, {\"url\": \"http://www.mongolbox.com/oblivion-2013-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80\", \"positives\": 2, \"total\": 38, \"scan_date\": \"2013-09-06 01:04:44\"}, {\"url\": \"http://www.mongolbox.com/texas-chainsaw-3d-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80\", \"positives\": 2, \"total\": 38, \"scan_date\": \"2013-09-05 20:08:01\"}, {\"url\": \"http://www.itunesgiftcard4u.com/login/245989bb82bb47644f9eb821b3814c3b/index1.php\", \"positives\": 8, \"total\": 38, \"scan_date\": \"2013-09-05 15:57:03\"}, {\"url\": \"http://www.mongolbox.com/%D0%BC%D0%B0%D1%81%D0%BA-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 2, \"total\": 37, \"scan_date\": \"2013-09-05 13:20:58\"}, {\"url\": \"http://www.mongolbox.com/%D0%B0%D0%BC%D1%8C%D0%B4%D1%80%D0%B0%D0%BB-%D1%82%D3%A9%D1%81%D3%A9%D0%BB-%D0%BC%D1%83%D1%81%D0%BA/\", \"positives\": 2, \"total\": 37, \"scan_date\": \"2013-09-05 13:07:24\"}, {\"url\": \"http://www.itunesgiftcard4u.com/login/4422b7be9accb552d81176e73874d586/login.php?errors2=1\", \"positives\": 5, \"total\": 39, \"scan_date\": \"2013-09-03 23:06:34\"}, {\"url\": \"http://www.itunesgiftcard4u.com/login/245989bb82bb47644f9eb821b3814c3b/\", \"positives\": 3, \"total\": 39, \"scan_date\": \"2013-09-03 23:06:30\"}, {\"url\": \"http://www.itunesgiftcard4u.com/login/\", \"positives\": 3, \"total\": 39, \"scan_date\": \"2013-09-03 23:06:30\"}, {\"url\": \"http://www.mongolbox.com/lost-in-thailand-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D0%B0%D0%B4%D0%BC%D0%B0%D0%BB\", \"positives\": 2, \"total\": 38, \"scan_date\": \"2013-09-03 16:30:37\"}, {\"url\": \"http://mongolbox.com/\", \"positives\": 1, \"total\": 39, \"scan_date\": \"2013-08-30 14:58:09\"}, {\"url\": \"http://www.mongolbox.com/sample-page/\", \"positives\": 1, \"total\": 39, \"scan_date\": \"2013-08-29 13:56:25\"}, {\"url\": \"http://www.mongolbox.com/devil-in-me-%D0%BC%D0%BE%D0%BD%D0%B3%D0%BE%D0%BB-%D1%85%D1%8D%D0%BB%D1%8D%D1%8D%D1%80/\", \"positives\": 1, \"total\": 37, \"scan_date\": \"2013-08-28 13:56:59\"}, {\"url\": \"http://www.mongolbox.com/category/%D0%B0%D0%B9%D0%BC%D1%88%D0%B3%D0%B8%D0%B9%D0%BD/\", \"positives\": 1, \"total\": 37, \"scan_date\": \"2013-08-28 13:57:00\"}, {\"url\": \"http://mahamegha.net/\", \"positives\": 2, \"total\": 39, \"scan_date\": \"2013-08-26 00:18:10\"}, {\"url\": \"http://betakeys-giveaway.com/wildstarbetakeys/%E2%80%8E\", \"positives\": 1, \"total\": 37, \"scan_date\": \"2013-08-22 09:06:42\"}, {\"url\": \"http://ljkclikthru.44qs.com/\", \"positives\": 1, \"total\": 38, \"scan_date\": \"2013-08-14 10:54:13\"}, {\"url\": \"http://ljkclikthru.44qs.com/multi-keygen1.2.exe\", \"positives\": 1, \"total\": 38, \"scan_date\": \"2013-08-13 07:03:57\"}, {\"url\": \"http://www.itunesgiftcard4u.com/connect/ppp/9dfb4bf46d4b65d6f8sxd6sdvhnh5t4r6drg46s5efa5da6w6aw8d46a32sf1e89gt/\", \"positives\": 3, \"total\": 38, \"scan_date\": \"2013-08-03 10:23:47\"}, {\"url\": \"http://www.itunesgiftcard4u.com/connect/ppp/9dfb4bf46d4b65d6f8sxd6sdvhnh5t4r6drg46s5efa5da6w6aw8d46a32sf1e89gt/login.htm\", \"positives\": 8, \"total\": 38, \"scan_date\": \"2013-08-03 10:23:47\"}, {\"url\": \"http://www.ntt62.com/paypal.com.au.ftp6/\", \"positives\": 7, \"total\": 39, \"scan_date\": \"2013-07-23 17:54:13\"}, {\"url\": \"http://ntt62.com/paypal.com.au.ftp6/initthi.html?cmd=SignIn&co_partnerId=2&pUserId=&siteid=0&pageType=&pa1=&i1=&bshowgif=&UsingSSL=&ru=&pp=&pa2=&errmsg=&runame=%5C%5C\", \"positives\": 6, \"total\": 39, \"scan_date\": \"2013-07-23 16:31:12\"}], \"resolutions\": [{\"last_resolved\": \"2013-09-14 00:00:00\", \"hostname\": \"1-qc.net\"}, {\"last_resolved\": \"2013-09-18 00:00:00\", \"hostname\": \"3vrealty.com\"}, {\"last_resolved\": \"2014-03-10 00:00:00\", \"hostname\": \"a1lightning.com\"}, {\"last_resolved\": \"2014-02-10 00:00:00\", \"hostname\": \"al-bader.net\"}, {\"last_resolved\": \"2014-03-19 00:00:00\", \"hostname\": \"alidaskitchen.com\"}, {\"last_resolved\": \"2014-08-19 00:00:00\", \"hostname\": \"amidax.com\"}, {\"last_resolved\": \"2014-08-11 00:00:00\", \"hostname\": \"arkpizarro.com\"}, {\"last_resolved\": \"2014-03-23 00:00:00\", \"hostname\": \"ashlandcomedy.com\"}, {\"last_resolved\": \"2014-03-28 00:00:00\", \"hostname\": \"atelierdepaine.ro\"}, {\"last_resolved\": \"2014-07-27 00:00:00\", \"hostname\": \"austinbay.net\"}, {\"last_resolved\": \"2014-03-04 00:00:00\", \"hostname\": \"axelera.eu\"}, {\"last_resolved\": \"2014-07-27 00:00:00\", \"hostname\": \"backdoorjobs.com\"}, {\"last_resolved\": \"2013-09-17 00:00:00\", \"hostname\": \"bayviewdentalny.com\"}, {\"last_resolved\": \"2014-03-11 00:00:00\", \"hostname\": \"beautyfitnessfoodie.com\"}, {\"last_resolved\": \"2013-08-22 00:00:00\", \"hostname\": \"betakeys-giveaway.com\"}, {\"last_resolved\": \"2014-05-29 00:00:00\", \"hostname\": \"blog.yoursabbatical.com\"}, {\"last_resolved\": \"2013-12-20 00:00:00\", \"hostname\": \"bluedogrescue.com\"}, {\"last_resolved\": \"2013-10-22 00:00:00\", \"hostname\": \"bonotv.net\"}, {\"last_resolved\": \"2014-08-04 00:00:00\", \"hostname\": \"box858.bluehost.com\"}, {\"last_resolved\": \"2014-03-11 00:00:00\", \"hostname\": \"brightring.com\"}, {\"last_resolved\": \"2014-03-11 00:00:00\", \"hostname\": \"bukur.com\"}, {\"last_resolved\": \"2014-03-11 00:00:00\", \"hostname\": \"casaabril.com\"}, {\"last_resolved\": \"2014-03-11 00:00:00\", \"hostname\": \"casserole-recipes.net\"}, {\"last_resolved\": \"2014-04-10 00:00:00\", \"hostname\": \"catmoseprimary.com\"}, {\"last_resolved\": \"2013-09-01 00:00:00\", \"hostname\": \"chapcare.org\"}, {\"last_resolved\": \"2014-02-12 00:00:00\", \"hostname\": \"chezlysa.com\"}, {\"last_resolved\": \"2014-05-14 00:00:00\", \"hostname\": \"chizys-spyware.com\"}, {\"last_resolved\": \"2014-03-30 00:00:00\", \"hostname\": \"clickkhongthuocla.vn\"}, {\"last_resolved\": \"2013-09-24 00:00:00\", \"hostname\": \"clinicaminnesota.com.mx\"}, {\"last_resolved\": \"2014-07-30 00:00:00\", \"hostname\": \"cobcf.org\"}, {\"last_resolved\": \"2014-02-13 00:00:00\", \"hostname\": \"cogentys.com\"}, {\"last_resolved\": \"2014-04-11 00:00:00\", \"hostname\": \"coniga.com\"}, {\"last_resolved\": \"2014-03-07 00:00:00\", \"hostname\": \"constructionshows.com\"}, {\"last_resolved\": \"2013-12-23 00:00:00\", \"hostname\": \"cricforum.com\"}, {\"last_resolved\": \"2014-05-13 00:00:00\", \"hostname\": \"crossfitlocal.com\"}, {\"last_resolved\": \"2014-06-06 00:00:00\", \"hostname\": \"dailyps.com\"}, {\"last_resolved\": \"2014-02-09 00:00:00\", \"hostname\": \"dailysikhupdates.com\"}, {\"last_resolved\": \"2014-08-19 00:00:00\", \"hostname\": \"dancewithheidi.com\"}, {\"last_resolved\": \"2014-05-19 00:00:00\", \"hostname\": \"danzacristiana.net\"}, {\"last_resolved\": \"2014-04-11 00:00:00\", \"hostname\": \"digitalmanagementblog.com\"}, {\"last_resolved\": \"2014-06-09 00:00:00\", \"hostname\": \"donnacardillo.com\"}, {\"last_resolved\": \"2013-11-11 00:00:00\", \"hostname\": \"dtiluxury.com\"}, {\"last_resolved\": \"2014-05-15 00:00:00\", \"hostname\": \"dubaiphotos.cc\"}, {\"last_resolved\": \"2014-02-13 00:00:00\", \"hostname\": \"dubisthai.com\"}, {\"last_resolved\": \"2013-11-21 00:00:00\", \"hostname\": \"elitehacks.fr\"}, {\"last_resolved\": \"2014-02-24 00:00:00\", \"hostname\": \"energyui.com\"}, {\"last_resolved\": \"2014-07-23 00:00:00\", \"hostname\": \"evolutionmktgrva.com\"}, {\"last_resolved\": \"2014-01-31 00:00:00\", \"hostname\": \"faizsulaiman.com\"}, {\"last_resolved\": \"2014-07-25 00:00:00\", \"hostname\": \"fifa14-coins.fashionern.com\"}, {\"last_resolved\": \"2014-02-15 00:00:00\", \"hostname\": \"firstfinancialplus.com\"}, {\"last_resolved\": \"2014-07-02 00:00:00\", \"hostname\": \"font-clipart.com\"}, {\"last_resolved\": \"2014-04-30 00:00:00\", \"hostname\": \"haradamethod.org\"}, {\"last_resolved\": \"2014-08-11 00:00:00\", \"hostname\": \"hathorsystrum.com\"}, {\"last_resolved\": \"2014-08-19 00:00:00\", \"hostname\": \"highstreetonmarket.com\"}, {\"last_resolved\": \"2014-07-15 00:00:00\", \"hostname\": \"ilovesylhet.net\"}, {\"last_resolved\": \"2014-07-22 00:00:00\", \"hostname\": \"in-game-gold.com\"}, {\"last_resolved\": \"2014-03-26 00:00:00\", \"hostname\": \"init4thelongrun.com\"}, {\"last_resolved\": \"2014-03-07 00:00:00\", \"hostname\": \"inlifes.com\"}, {\"last_resolved\": \"2013-09-12 00:00:00\", \"hostname\": \"itunesgiftcard4u.com\"}, {\"last_resolved\": \"2013-07-27 00:00:00\", \"hostname\": \"kitzig.com.sg\"}, {\"last_resolved\": \"2014-05-26 00:00:00\", \"hostname\": \"lapnl-ca.eyemovementactualization.com\"}, {\"last_resolved\": \"2014-05-26 00:00:00\", \"hostname\": \"lapnl.ca\"}, {\"last_resolved\": \"2014-03-26 00:00:00\", \"hostname\": \"lifeasethel.com\"}, {\"last_resolved\": \"2014-03-17 00:00:00\", \"hostname\": \"lisanoser-fotografie.com\"}, {\"last_resolved\": \"2014-07-30 00:00:00\", \"hostname\": \"littlepunkpeople.net\"}, {\"last_resolved\": \"2013-08-14 00:00:00\", \"hostname\": \"ljkclikthru.44qs.com\"}, {\"last_resolved\": \"2014-03-08 00:00:00\", \"hostname\": \"lorehunter.com\"}, {\"last_resolved\": \"2014-04-09 00:00:00\", \"hostname\": \"lotusmediacentre.com\"}, {\"last_resolved\": \"2014-07-21 00:00:00\", \"hostname\": \"lslinstruments.org\"}, {\"last_resolved\": \"2014-06-03 00:00:00\", \"hostname\": \"lustzuessen.com\"}, {\"last_resolved\": \"2013-12-25 00:00:00\", \"hostname\": \"macorisdelmar.com\"}, {\"last_resolved\": \"2014-03-12 00:00:00\", \"hostname\": \"madmaxxkillerpicks.com\"}, {\"last_resolved\": \"2013-11-25 00:00:00\", \"hostname\": \"mahamegha.com\"}, {\"last_resolved\": \"2013-09-09 00:00:00\", \"hostname\": \"mahamegha.info\"}, {\"last_resolved\": \"2014-02-15 00:00:00\", \"hostname\": \"mahamegha.lk\"}, {\"last_resolved\": \"2013-08-26 00:00:00\", \"hostname\": \"mahamegha.net\"}, {\"last_resolved\": \"2013-11-28 00:00:00\", \"hostname\": \"mahamegha.org\"}, {\"last_resolved\": \"2014-07-10 00:00:00\", \"hostname\": \"marshallhabba.com\"}, {\"last_resolved\": \"2014-08-04 00:00:00\", \"hostname\": \"mauriweb.info\"}, {\"last_resolved\": \"2014-03-10 00:00:00\", \"hostname\": \"medicine.mytau.org\"}, {\"last_resolved\": \"2014-07-22 00:00:00\", \"hostname\": \"medini.org\"}, {\"last_resolved\": \"2014-04-29 00:00:00\", \"hostname\": \"melzsalon.com\"}, {\"last_resolved\": \"2014-04-11 00:00:00\", \"hostname\": \"middleclassjoe.com\"}, {\"last_resolved\": \"2014-07-29 00:00:00\", \"hostname\": \"minctrack.com\"}, {\"last_resolved\": \"2014-01-02 00:00:00\", \"hostname\": \"mindset.yoursabbatical.com\"}, {\"last_resolved\": \"2014-08-14 00:00:00\", \"hostname\": \"minipcr.com\"}, {\"last_resolved\": \"2013-09-29 00:00:00\", \"hostname\": \"mitsubishielectric.com.vn\"}, {\"last_resolved\": \"2014-07-20 00:00:00\", \"hostname\": \"monamye.com\"}, {\"last_resolved\": \"2013-08-30 00:00:00\", \"hostname\": \"mongolbox.com\"}, {\"last_resolved\": \"2014-05-22 00:00:00\", \"hostname\": \"montgomery1.com\"}, {\"last_resolved\": \"2013-11-09 00:00:00\", \"hostname\": \"mp3sell.com\"}, {\"last_resolved\": \"2013-07-23 00:00:00\", \"hostname\": \"ntt62.com\"}, {\"last_resolved\": \"2014-02-14 00:00:00\", \"hostname\": \"oldtimedays.com\"}, {\"last_resolved\": \"2013-11-20 00:00:00\", \"hostname\": \"outfog.com\"}, {\"last_resolved\": \"2014-08-12 00:00:00\", \"hostname\": \"partiuintercambio.org\"}, {\"last_resolved\": \"2014-04-23 00:00:00\", \"hostname\": \"polygamybooks-power.com\"}, {\"last_resolved\": \"2014-07-21 00:00:00\", \"hostname\": \"poodspoo.com\"}, {\"last_resolved\": \"2014-04-29 00:00:00\", \"hostname\": \"princetonmedicine.com\"}, {\"last_resolved\": \"2013-07-13 00:00:00\", \"hostname\": \"rdbresources.com\"}, {\"last_resolved\": \"2014-08-14 00:00:00\", \"hostname\": \"redskycafe.com\"}, {\"last_resolved\": \"2014-08-01 00:00:00\", \"hostname\": \"rhymeswithgeek.com\"}, {\"last_resolved\": \"2014-08-14 00:00:00\", \"hostname\": \"rwbooth.com\"}, {\"last_resolved\": \"2014-07-04 00:00:00\", \"hostname\": \"sandsmodelsshop.com\"}, {\"last_resolved\": \"2014-05-09 00:00:00\", \"hostname\": \"sillyplace.net\"}, {\"last_resolved\": \"2014-07-14 00:00:00\", \"hostname\": \"sofiachich.com\"}, {\"last_resolved\": \"2014-03-11 00:00:00\", \"hostname\": \"tahya.com\"}, {\"last_resolved\": \"2014-04-01 00:00:00\", \"hostname\": \"teainengland.com\"}, {\"last_resolved\": \"2014-03-24 00:00:00\", \"hostname\": \"techidiocy.com\"}, {\"last_resolved\": \"2014-02-25 00:00:00\", \"hostname\": \"techietape.com\"}, {\"last_resolved\": \"2014-01-02 00:00:00\", \"hostname\": \"telechargement-fr.us\"}, {\"last_resolved\": \"2014-06-15 00:00:00\", \"hostname\": \"thebostonfacepainters.com\"}, {\"last_resolved\": \"2014-07-15 00:00:00\", \"hostname\": \"thehealthyandfithomeschoolmom.com\"}, {\"last_resolved\": \"2014-05-26 00:00:00\", \"hostname\": \"thetopfivepercent.com\"}, {\"last_resolved\": \"2014-08-20 00:00:00\", \"hostname\": \"thisbluebird.com\"}, {\"last_resolved\": \"2014-04-03 00:00:00\", \"hostname\": \"thisfitsme.com\"}, {\"last_resolved\": \"2014-07-14 00:00:00\", \"hostname\": \"totalrespiratoryandrehab.com\"}, {\"last_resolved\": \"2014-06-18 00:00:00\", \"hostname\": \"trendmaniamarketing.com\"}, {\"last_resolved\": \"2013-12-10 00:00:00\", \"hostname\": \"vasisdas.com\"}, {\"last_resolved\": \"2014-03-21 00:00:00\", \"hostname\": \"vitranet.com.vn\"}, {\"last_resolved\": \"2013-11-11 00:00:00\", \"hostname\": \"weeshare.net\"}, {\"last_resolved\": \"2014-07-28 00:00:00\", \"hostname\": \"wisabet.com\"}, {\"last_resolved\": \"2013-11-11 00:00:00\", \"hostname\": \"womenintheboardroom.com\"}, {\"last_resolved\": \"2014-04-09 00:00:00\", \"hostname\": \"wornout-soles.com\"}, {\"last_resolved\": \"2014-06-23 00:00:00\", \"hostname\": \"www.80diapers.com\"}, {\"last_resolved\": \"2014-03-20 00:00:00\", \"hostname\": \"www.accpf.cl\"}, {\"last_resolved\": \"2014-04-23 00:00:00\", \"hostname\": \"www.accurateluxury.com\"}, {\"last_resolved\": \"2014-08-01 00:00:00\", \"hostname\": \"www.austinbay.net\"}, {\"last_resolved\": \"2014-08-11 00:00:00\", \"hostname\": \"www.avant-gardehomeconstruction.com\"}, {\"last_resolved\": \"2014-07-02 00:00:00\", \"hostname\": \"www.bagpipestand.com\"}, {\"last_resolved\": \"2014-08-21 00:00:00\", \"hostname\": \"www.balqastud.com\"}, {\"last_resolved\": \"2014-06-04 00:00:00\", \"hostname\": \"www.billygoboy.com\"}, {\"last_resolved\": \"2013-09-30 00:00:00\", \"hostname\": \"www.brightlightsrun.com\"}, {\"last_resolved\": \"2014-06-30 00:00:00\", \"hostname\": \"www.brightring.com\"}, {\"last_resolved\": \"2014-07-29 00:00:00\", \"hostname\": \"www.caribbeanfashionspot.com\"}, {\"last_resolved\": \"2013-09-01 00:00:00\", \"hostname\": \"www.chapcare.org\"}, {\"last_resolved\": \"2014-03-06 00:00:00\", \"hostname\": \"www.civilfreedoms.org\"}, {\"last_resolved\": \"2013-09-24 00:00:00\", \"hostname\": \"www.clinicaminnesota.com.mx\"}, {\"last_resolved\": \"2014-06-02 00:00:00\", \"hostname\": \"www.communitymarketing.ca\"}, {\"last_resolved\": \"2014-06-21 00:00:00\", \"hostname\": \"www.constructionshows.com\"}, {\"last_resolved\": \"2014-06-14 00:00:00\", \"hostname\": \"www.coquitlammartialarts.com\"}, {\"last_resolved\": \"2014-06-19 00:00:00\", \"hostname\": \"www.costaricaunlimited.com\"}, {\"last_resolved\": \"2014-04-21 00:00:00\", \"hostname\": \"www.cyberoperator.com\"}, {\"last_resolved\": \"2014-07-13 00:00:00\", \"hostname\": \"www.daughterofzionforever.com\"}, {\"last_resolved\": \"2014-05-18 00:00:00\", \"hostname\": \"www.davefowliestravelblog.com\"}, {\"last_resolved\": \"2014-07-30 00:00:00\", \"hostname\": \"www.discoursmariage.net\"}, {\"last_resolved\": \"2014-01-31 00:00:00\", \"hostname\": \"www.diverticine.com\"}, {\"last_resolved\": \"2014-08-21 00:00:00\", \"hostname\": \"www.dumpeddaily.com\"}, {\"last_resolved\": \"2014-07-02 00:00:00\", \"hostname\": \"www.e-howtogetridofdandruff.com\"}, {\"last_resolved\": \"2014-07-17 00:00:00\", \"hostname\": \"www.ecostings.com\"}, {\"last_resolved\": \"2014-07-18 00:00:00\", \"hostname\": \"www.fajrpress.net\"}, {\"last_resolved\": \"2013-12-20 00:00:00\", \"hostname\": \"www.farn.org.ar\"}, {\"last_resolved\": \"2014-08-18 00:00:00\", \"hostname\": \"www.findingahealingplace.com\"}, {\"last_resolved\": \"2014-08-12 00:00:00\", \"hostname\": \"www.game-gold-reviews.com\"}, {\"last_resolved\": \"2014-05-29 00:00:00\", \"hostname\": \"www.gozdat.com\"}, {\"last_resolved\": \"2014-08-11 00:00:00\", \"hostname\": \"www.hathorsystrum.com\"}, {\"last_resolved\": \"2014-06-02 00:00:00\", \"hostname\": \"www.hijosyalimentacion.com\"}, {\"last_resolved\": \"2014-04-17 00:00:00\", \"hostname\": \"www.homegrownfamilies.net\"}, {\"last_resolved\": \"2014-08-11 00:00:00\", \"hostname\": \"www.hypnotherapyperth.net\"}, {\"last_resolved\": \"2014-06-10 00:00:00\", \"hostname\": \"www.intraipsum.se\"}, {\"last_resolved\": \"2014-06-17 00:00:00\", \"hostname\": \"www.itilandme.com\"}, {\"last_resolved\": \"2013-09-05 00:00:00\", \"hostname\": \"www.itunesgiftcard4u.com\"}, {\"last_resolved\": \"2014-06-25 00:00:00\", \"hostname\": \"www.keedarwhittle.com\"}, {\"last_resolved\": \"2014-03-17 00:00:00\", \"hostname\": \"www.lisanoser-fotografie.ch\"}, {\"last_resolved\": \"2013-08-16 00:00:00\", \"hostname\": \"www.lslinstruments.org\"}, {\"last_resolved\": \"2014-08-14 00:00:00\", \"hostname\": \"www.macorisdelmar.com\"}, {\"last_resolved\": \"2014-01-23 00:00:00\", \"hostname\": \"www.mahamegha.lk\"}, {\"last_resolved\": \"2014-04-10 00:00:00\", \"hostname\": \"www.mesalocksmithpros.net\"}, {\"last_resolved\": \"2014-06-03 00:00:00\", \"hostname\": \"www.michaelhugganphotography.com\"}, {\"last_resolved\": \"2013-09-14 00:00:00\", \"hostname\": \"www.mongolbox.com\"}, {\"last_resolved\": \"2014-07-22 00:00:00\", \"hostname\": \"www.morriscountyclerk.org\"}, {\"last_resolved\": \"2014-07-17 00:00:00\", \"hostname\": \"www.mritechnologies.com\"}, {\"last_resolved\": \"2013-07-23 00:00:00\", \"hostname\": \"www.ntt62.com\"}, {\"last_resolved\": \"2014-05-25 00:00:00\", \"hostname\": \"www.nufollowers.com\"}, {\"last_resolved\": \"2014-06-10 00:00:00\", \"hostname\": \"www.oasishoteles.net\"}, {\"last_resolved\": \"2014-01-12 00:00:00\", \"hostname\": \"www.pcspress.com\"}, {\"last_resolved\": \"2014-01-10 00:00:00\", \"hostname\": \"www.phoenixhiphop.net\"}, {\"last_resolved\": \"2014-06-16 00:00:00\", \"hostname\": \"www.posturecorrectorcenter.com\"}, {\"last_resolved\": \"2014-06-27 00:00:00\", \"hostname\": \"www.primecareinternalmed.com\"}, {\"last_resolved\": \"2014-05-20 00:00:00\", \"hostname\": \"www.princetonmedicine.com\"}, {\"last_resolved\": \"2014-06-27 00:00:00\", \"hostname\": \"www.readathomemama.com\"}, {\"last_resolved\": \"2014-07-30 00:00:00\", \"hostname\": \"www.rhymeswithgeek.com\"}, {\"last_resolved\": \"2014-08-21 00:00:00\", \"hostname\": \"www.rjhaddy.com\"}, {\"last_resolved\": \"2014-03-11 00:00:00\", \"hostname\": \"www.soriba.org\"}, {\"last_resolved\": \"2014-06-28 00:00:00\", \"hostname\": \"www.springboardforthearts.org\"}, {\"last_resolved\": \"2014-02-01 00:00:00\", \"hostname\": \"www.staffing-direct-deposit.com\"}, {\"last_resolved\": \"2014-02-05 00:00:00\", \"hostname\": \"www.succinctfp.com\"}, {\"last_resolved\": \"2014-05-19 00:00:00\", \"hostname\": \"www.tabatatraining.com\"}, {\"last_resolved\": \"2014-06-13 00:00:00\", \"hostname\": \"www.tevacare.com\"}, {\"last_resolved\": \"2014-05-23 00:00:00\", \"hostname\": \"www.travelsaveworld.com\"}, {\"last_resolved\": \"2014-05-23 00:00:00\", \"hostname\": \"www.village-greens-coop.co.uk\"}, {\"last_resolved\": \"2013-08-05 00:00:00\", \"hostname\": \"www.virginiacarclub.com\"}, {\"last_resolved\": \"2014-04-20 00:00:00\", \"hostname\": \"www.vitranet.com.vn\"}, {\"last_resolved\": \"2013-09-26 00:00:00\", \"hostname\": \"www.wayoffgrid.com\"}, {\"last_resolved\": \"2014-06-22 00:00:00\", \"hostname\": \"www.weeshare.net\"}, {\"last_resolved\": \"2014-01-15 00:00:00\", \"hostname\": \"xenonart.com\"}, {\"last_resolved\": \"2014-05-30 00:00:00\", \"hostname\": \"yoursabbatical.com\"}], \"verbose_msg\": \"IP address found in dataset\"}\n";
        final Response responseWrapper = new Response(200, mockResponse, null);
        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenReturn(responseWrapper);

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        IPAddressReport report = virusTotalRef.getIPAddresReport("69.195.124.58");

        assertEquals(report.getResponseCode(), 1);
        assertNotNull(report.getVerboseMessage());
        Sample[] undetectedDownloadedSamples = report.getUndetectedDownloadedSamples();
        assertSample(undetectedDownloadedSamples[0]);
        assertSample(undetectedDownloadedSamples[1]);
        assertSample(undetectedDownloadedSamples[2]);
        assertSample(undetectedDownloadedSamples[3]);
        assertSample(undetectedDownloadedSamples[4]);
        assertSample(undetectedDownloadedSamples[5]);

        Sample[] detectedDownloadedSamples = report.getDetectedDownloadedSamples();
        assertSample(detectedDownloadedSamples[0]);
        assertSample(detectedDownloadedSamples[1]);

        IPAddressResolution[] resolutions = report.getResolutions();
        assertResolution(resolutions[0]);
        assertResolution(resolutions[1]);
        assertResolution(resolutions[2]);
        assertResolution(resolutions[3]);
        assertResolution(resolutions[4]);
        assertResolution(resolutions[5]);

        URL[] detectedUrls = report.getDetectedUrls();
        assertUrl(detectedUrls[0]);
        assertUrl(detectedUrls[1]);
        assertUrl(detectedUrls[2]);
        assertUrl(detectedUrls[3]);
        assertUrl(detectedUrls[4]);
        assertUrl(detectedUrls[5]);
    }

    @Test
    public void testMakeAComment() throws Exception {
        String mockResponse = "{\"response_code\": 1, \"verbose_msg\": \"Your comment was successfully posted\"}\n";

        final Response responseWrapper = new Response(200, mockResponse, null);
        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenReturn(responseWrapper);

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        GeneralResponse generalResponse = virusTotalRef.makeAComment("resource", "some comment");
        assertNotNull(generalResponse.getVerboseMessage());
        assertEquals(generalResponse.getResponseCode(), 1);
    }

    @Test
    public void testScanUrls() throws Exception {
        String mockResponse = "[{\"permalink\": \"https://www.virustotal.com/url/a8973d30cca00594def448e23564d25d9ea35ed4014d3bce23a0d74aa2d11cb1/analysis/1408725581/\", \"resource\": \"http://www.google.lk/\", \"url\": \"http://www.google.lk/\", \"response_code\": 1, \"scan_date\": \"2014-08-22 16:39:41\", \"scan_id\": \"a8973d30cca00594def448e23564d25d9ea35ed4014d3bce23a0d74aa2d11cb1-1408725581\", \"verbose_msg\": \"Scan request successfully queued, come back later for the report\"}, {\"permalink\": \"https://www.virustotal.com/url/ed91698b5823a5e4424726955dd3fd437d9cfdc46f7b8988cded5da779cc7483/analysis/1408725581/\", \"resource\": \"http://www.yahoo.com/\", \"url\": \"http://www.yahoo.com/\", \"response_code\": 1, \"scan_date\": \"2014-08-22 16:39:41\", \"scan_id\": \"ed91698b5823a5e4424726955dd3fd437d9cfdc46f7b8988cded5da779cc7483-1408725581\", \"verbose_msg\": \"Scan request successfully queued, come back later for the report\"}]\n";
        final Response responseWrapper = new Response(200, mockResponse, null);
        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenReturn(responseWrapper);

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        String urls[] = {"http://www.google.lk/", "http://www.yahoo.com/"};
        ScanInfo[] scanInfoArr = virusTotalRef.scanUrls(urls);

        assertScanInfo(scanInfoArr[0], urls[0]);
        assertScanInfo(scanInfoArr[1], urls[1]);
    }

    @Test
    public void testUrlScanReport() throws Exception {
        String mockResponse = "[{\"permalink\": \"https://www.virustotal.com/url/70ae5b6b9e263a4b4ed2bcdf0b2f5242bc7d660e3f8a3637921cbb72727b0f83/analysis/1408707716/\", \"url\": \"http://www.toll-net.be/\", \"response_code\": 1, \"scan_date\": \"2014-08-22 11:41:56\", \"scan_id\": \"70ae5b6b9e263a4b4ed2bcdf0b2f5242bc7d660e3f8a3637921cbb72727b0f83-1408707716\", \"verbose_msg\": \"Scan finished, scan information embedded in this object\", \"filescan_id\": null, \"positives\": 4, \"total\": 58, \"scans\": {\"CLEAN MX\": {\"detected\": false, \"result\": \"clean site\"}, \"MalwarePatrol\": {\"detected\": false, \"result\": \"clean site\"}, \"ZDB Zeus\": {\"detected\": false, \"result\": \"clean site\"}, \"Tencent\": {\"detected\": false, \"result\": \"clean site\"}, \"AutoShun\": {\"detected\": false, \"result\": \"unrated site\"}, \"ZCloudsec\": {\"detected\": false, \"result\": \"clean site\"}, \"K7AntiVirus\": {\"detected\": false, \"result\": \"clean site\"}, \"Quttera\": {\"detected\": true, \"result\": \"malicious site\"}, \"AegisLab WebGuard\": {\"detected\": false, \"result\": \"clean site\"}, \"MalwareDomainList\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"http://www.malwaredomainlist.com/mdl.php?search=www.toll-net.be\"}, \"ZeusTracker\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"https://zeustracker.abuse.ch/monitor.php?host=www.toll-net.be\"}, \"zvelo\": {\"detected\": false, \"result\": \"clean site\"}, \"Google Safebrowsing\": {\"detected\": false, \"result\": \"clean site\"}, \"Kaspersky\": {\"detected\": false, \"result\": \"unrated site\"}, \"BitDefender\": {\"detected\": true, \"result\": \"malware site\"}, \"Dr.Web\": {\"detected\": false, \"result\": \"clean site\"}, \"ADMINUSLabs\": {\"detected\": false, \"result\": \"clean site\"}, \"C-SIRT\": {\"detected\": false, \"result\": \"clean site\"}, \"OpenPhish\": {\"detected\": false, \"result\": \"clean site\"}, \"Websense ThreatSeeker\": {\"detected\": false, \"result\": \"unrated site\"}, \"VX Vault\": {\"detected\": false, \"result\": \"clean site\"}, \"Webutation\": {\"detected\": false, \"result\": \"clean site\"}, \"Trustwave\": {\"detected\": false, \"result\": \"unrated site\"}, \"Web Security Guard\": {\"detected\": false, \"result\": \"clean site\"}, \"G-Data\": {\"detected\": false, \"result\": \"clean site\"}, \"Malwarebytes hpHosts\": {\"detected\": true, \"result\": \"malware site\"}, \"Wepawet\": {\"detected\": false, \"result\": \"unrated site\"}, \"AlienVault\": {\"detected\": false, \"result\": \"clean site\"}, \"Emsisoft\": {\"detected\": false, \"result\": \"clean site\"}, \"Malc0de Database\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"http://malc0de.com/database/index.php?search=www.toll-net.be\"}, \"SpyEyeTracker\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"https://spyeyetracker.abuse.ch/monitor.php?host=www.toll-net.be\"}, \"malwares.com URL checker\": {\"detected\": false, \"result\": \"clean site\"}, \"Phishtank\": {\"detected\": false, \"result\": \"clean site\"}, \"Malwared\": {\"detected\": false, \"result\": \"clean site\"}, \"Avira\": {\"detected\": false, \"result\": \"clean site\"}, \"CyberCrime\": {\"detected\": false, \"result\": \"clean site\"}, \"Antiy-AVL\": {\"detected\": false, \"result\": \"clean site\"}, \"SCUMWARE.org\": {\"detected\": false, \"result\": \"clean site\"}, \"FraudSense\": {\"detected\": false, \"result\": \"clean site\"}, \"Opera\": {\"detected\": false, \"result\": \"clean site\"}, \"Comodo Site Inspector\": {\"detected\": false, \"result\": \"clean site\"}, \"Malekal\": {\"detected\": false, \"result\": \"clean site\"}, \"ESET\": {\"detected\": false, \"result\": \"clean site\"}, \"Sophos\": {\"detected\": false, \"result\": \"unrated site\"}, \"Yandex Safebrowsing\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"http://yandex.com/infected?l10n=en&url=http://www.toll-net.be/\"}, \"SecureBrain\": {\"detected\": false, \"result\": \"clean site\"}, \"Malware Domain Blocklist\": {\"detected\": false, \"result\": \"clean site\"}, \"Netcraft\": {\"detected\": false, \"result\": \"unrated site\"}, \"PalevoTracker\": {\"detected\": false, \"result\": \"clean site\"}, \"CRDF\": {\"detected\": false, \"result\": \"clean site\"}, \"ThreatHive\": {\"detected\": false, \"result\": \"clean site\"}, \"ParetoLogic\": {\"detected\": false, \"result\": \"clean site\"}, \"Rising\": {\"detected\": false, \"result\": \"clean site\"}, \"URLQuery\": {\"detected\": false, \"result\": \"unrated site\"}, \"StopBadware\": {\"detected\": false, \"result\": \"unrated site\"}, \"Sucuri SiteCheck\": {\"detected\": false, \"result\": \"clean site\"}, \"Fortinet\": {\"detected\": true, \"result\": \"malware site\"}, \"Spam404\": {\"detected\": false, \"result\": \"clean site\"}}}, {\"permalink\": \"https://www.virustotal.com/url/a8973d30cca00594def448e23564d25d9ea35ed4014d3bce23a0d74aa2d11cb1/analysis/1408725581/\", \"url\": \"http://www.google.lk/\", \"response_code\": 1, \"scan_date\": \"2014-08-22 16:39:41\", \"scan_id\": \"a8973d30cca00594def448e23564d25d9ea35ed4014d3bce23a0d74aa2d11cb1-1408725581\", \"verbose_msg\": \"Scan finished, scan information embedded in this object\", \"filescan_id\": null, \"positives\": 0, \"total\": 58, \"scans\": {\"CLEAN MX\": {\"detected\": false, \"result\": \"clean site\"}, \"MalwarePatrol\": {\"detected\": false, \"result\": \"clean site\"}, \"ZDB Zeus\": {\"detected\": false, \"result\": \"clean site\"}, \"Tencent\": {\"detected\": false, \"result\": \"clean site\"}, \"AutoShun\": {\"detected\": false, \"result\": \"unrated site\"}, \"ZCloudsec\": {\"detected\": false, \"result\": \"clean site\"}, \"K7AntiVirus\": {\"detected\": false, \"result\": \"clean site\"}, \"Quttera\": {\"detected\": false, \"result\": \"clean site\"}, \"AegisLab WebGuard\": {\"detected\": false, \"result\": \"clean site\"}, \"MalwareDomainList\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"http://www.malwaredomainlist.com/mdl.php?search=www.google.lk\"}, \"ZeusTracker\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"https://zeustracker.abuse.ch/monitor.php?host=www.google.lk\"}, \"zvelo\": {\"detected\": false, \"result\": \"clean site\"}, \"Google Safebrowsing\": {\"detected\": false, \"result\": \"clean site\"}, \"Kaspersky\": {\"detected\": false, \"result\": \"clean site\"}, \"BitDefender\": {\"detected\": false, \"result\": \"clean site\"}, \"Dr.Web\": {\"detected\": false, \"result\": \"clean site\"}, \"ADMINUSLabs\": {\"detected\": false, \"result\": \"clean site\"}, \"C-SIRT\": {\"detected\": false, \"result\": \"clean site\"}, \"OpenPhish\": {\"detected\": false, \"result\": \"clean site\"}, \"Websense ThreatSeeker\": {\"detected\": false, \"result\": \"clean site\"}, \"VX Vault\": {\"detected\": false, \"result\": \"clean site\"}, \"Webutation\": {\"detected\": false, \"result\": \"clean site\"}, \"Trustwave\": {\"detected\": false, \"result\": \"clean site\"}, \"Web Security Guard\": {\"detected\": false, \"result\": \"clean site\"}, \"G-Data\": {\"detected\": false, \"result\": \"clean site\"}, \"Malwarebytes hpHosts\": {\"detected\": false, \"result\": \"clean site\"}, \"Wepawet\": {\"detected\": false, \"result\": \"clean site\", \"detail\": null}, \"AlienVault\": {\"detected\": false, \"result\": \"clean site\"}, \"Emsisoft\": {\"detected\": false, \"result\": \"clean site\"}, \"Malc0de Database\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"http://malc0de.com/database/index.php?search=www.google.lk\"}, \"SpyEyeTracker\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"https://spyeyetracker.abuse.ch/monitor.php?host=www.google.lk\"}, \"malwares.com URL checker\": {\"detected\": false, \"result\": \"clean site\"}, \"Phishtank\": {\"detected\": false, \"result\": \"clean site\"}, \"Malwared\": {\"detected\": false, \"result\": \"clean site\"}, \"Avira\": {\"detected\": false, \"result\": \"clean site\"}, \"CyberCrime\": {\"detected\": false, \"result\": \"clean site\"}, \"Antiy-AVL\": {\"detected\": false, \"result\": \"clean site\"}, \"SCUMWARE.org\": {\"detected\": false, \"result\": \"clean site\"}, \"FraudSense\": {\"detected\": false, \"result\": \"clean site\"}, \"Opera\": {\"detected\": false, \"result\": \"clean site\"}, \"Comodo Site Inspector\": {\"detected\": false, \"result\": \"clean site\"}, \"Malekal\": {\"detected\": false, \"result\": \"clean site\"}, \"ESET\": {\"detected\": false, \"result\": \"clean site\"}, \"Sophos\": {\"detected\": false, \"result\": \"unrated site\"}, \"Yandex Safebrowsing\": {\"detected\": false, \"result\": \"clean site\", \"detail\": \"http://yandex.com/infected?l10n=en&url=http://www.google.lk/\"}, \"SecureBrain\": {\"detected\": false, \"result\": \"clean site\"}, \"Malware Domain Blocklist\": {\"detected\": false, \"result\": \"clean site\"}, \"Netcraft\": {\"detected\": false, \"result\": \"unrated site\"}, \"PalevoTracker\": {\"detected\": false, \"result\": \"clean site\"}, \"CRDF\": {\"detected\": false, \"result\": \"clean site\"}, \"ThreatHive\": {\"detected\": false, \"result\": \"clean site\"}, \"ParetoLogic\": {\"detected\": false, \"result\": \"clean site\"}, \"Rising\": {\"detected\": false, \"result\": \"clean site\"}, \"URLQuery\": {\"detected\": false, \"result\": \"unrated site\"}, \"StopBadware\": {\"detected\": false, \"result\": \"unrated site\"}, \"Sucuri SiteCheck\": {\"detected\": false, \"result\": \"clean site\"}, \"Fortinet\": {\"detected\": false, \"result\": \"unrated site\"}, \"Spam404\": {\"detected\": false, \"result\": \"clean site\"}}}]\n";
        final Response responseWrapper = new Response(200, mockResponse, null);
        when(httpRequestObject.request(
                anyString(),
                anyList(),
                anyList(),
                any(RequestMethod.class),
                anyList())).thenReturn(responseWrapper);

        VirusTotalConfig instance = VirusTotalConfig.getConfigInstance();
        instance.setVirusTotalAPIKey("apikey");
        VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl(httpRequestObject);
        String urls[] = {"http://www.toll-net.be/", "www.google.lk"};
        FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);

        assertFileScanReport(reports[0], null);
        assertFileScanReport(reports[1], null);
    }

    private void assertResolution(IPAddressResolution resolution) {
        assertNotNull(resolution.getHostName());
        assertNotNull(resolution.getLastResolved());
    }

    private void assertFileScanReport(FileScanReport fileScanReport, String resource) {
        assertEquals(fileScanReport.getResource(), resource);
        assertNotNull(fileScanReport.getScanId());
        assertNotNull(fileScanReport.getPermalink());
        assertNotNull(fileScanReport.getTotal());
        assertNotNull(fileScanReport.getPositives());
        assertTrue(fileScanReport.getScans().size() > 0);
        assertEquals(fileScanReport.getResponseCode(), new Integer(1));
        assertNotNull(fileScanReport.getScanDate());
        assertNotNull(fileScanReport.getVerboseMessage());
        assertTrue(fileScanReport.getTotal() >= 0);
    }

    private void assertUrl(URL detectedUrl) {
        assertNotNull(detectedUrl.getUrl());
        assertTrue(detectedUrl.getPositives() > 0);
        assertTrue(detectedUrl.getTotal() > 0);
        assertNotNull(detectedUrl.getScanDate());
    }

    private void assertDomainResolution(DomainResolution domainResolution) {
        assertNotNull(domainResolution.getLastResolved());
        assertNotNull(domainResolution.getIpAddress());
    }

    private void assertSample(Sample sample) {
        assertNotNull(sample.getDate());
        assertTrue(sample.getPositives() >= 0);
        assertTrue(sample.getTotal() > 0);
        assertTrue(sample.getTotal() > 0);
        assertNotNull(sample.getSha256());
    }
}
