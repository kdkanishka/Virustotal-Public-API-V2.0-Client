package systemtests;

import com.kanishka.virustotal.dto.DomainReport;
import com.kanishka.virustotal.dto.DomainResolution;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.Sample;
import com.kanishka.virustotal.dto.URL;
import com.kanishka.virustotal.dto.VirusScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.InvalidArguentsException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import com.kanishka.virustotalv2.VirusTotalConfig;
import com.kanishka.virustotalv2.VirustotalPublicV2;
import com.kanishka.virustotalv2.VirustotalPublicV2Impl;
import junit.framework.Assert;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import systemtests.config.ApiDetails;

import java.io.IOException;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * Created with IntelliJ IDEA.
 * User: kanishka
 * Date: 8/31/14
 * Time: 8:59 PM
 * To change this template use File | Settings | File Templates.
 */
public class VirusTotalServiceClientSystemTest {

    VirustotalPublicV2 virusTotalRef;

    @Before
    public final void setUp() throws APIKeyNotFoundException {
        VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(ApiDetails.API_KEY);
        virusTotalRef = new VirustotalPublicV2Impl();
    }

    @After
    public final void tearDown() {
        System.gc();
    }

    @Test
    public void it_should_return_domain_report_for_the_given_domain() throws
            QuotaExceededException, InvalidArguentsException,
            UnauthorizedAccessException, IOException {
        String someMaliciousDomain = "www.ntt62.com";
        DomainReport report = virusTotalRef.getDomainReport(someMaliciousDomain);

        Sample[] communicatingSamples = report.getDetectedCommunicatingSamples();
        if (communicatingSamples != null) {
            System.out.println("Communicating Samples");
            for (Sample sample : communicatingSamples) {
                System.out.println("SHA256 : " + sample.getSha256());
                System.out.println("Date : " + sample.getDate());
                System.out.println("Positives : " + sample.getPositives());
                System.out.println("Total : " + sample.getTotal());

                assertNotNull(sample.getSha256());
                assertNotNull(sample.getDate());
                assertTrue(sample.getPositives() > 0);
                assertTrue(sample.getTotal() > 0);
            }
        }

        Sample[] detectedDownloadedSamples = report.getDetectedDownloadedSamples();
        if (detectedDownloadedSamples != null) {
            System.out.println("Detected Downloaded Samples");
            for (Sample sample : detectedDownloadedSamples) {
                System.out.println("SHA256 : " + sample.getSha256());
                System.out.println("Date : " + sample.getDate());
                System.out.println("Positives : " + sample.getPositives());
                System.out.println("Total : " + sample.getTotal());

                assertNotNull(sample.getSha256());
                assertNotNull(sample.getDate());
                assertTrue(sample.getPositives() > 0);
                assertTrue(sample.getTotal() > 0);
            }
        }

        URL[] urls = report.getDetectedUrls();
        if (urls != null) {
            System.out.println("Detected URLs");
            for (URL url : urls) {
                System.out.println("URL : " + url.getUrl());
                System.out.println("Positives : " + url.getPositives());
                System.out.println("Total : " + url.getTotal());
                System.out.println("Scan Date" + url.getScanDate());

                assertNotNull(url.getUrl());
                assertTrue(url.getPositives() > 0);
                assertTrue(url.getTotal() > 0);
                assertNotNull(url.getScanDate());
            }
        }

        DomainResolution[] resolutions = report.getResolutions();
        if (resolutions != null) {
            System.out.println("Resolutions");
            for (DomainResolution resolution : resolutions) {
                System.out.println("IP Address : " + resolution.getIpAddress());
                System.out.println("Last Resolved : " + resolution.getLastResolved());
            }
        }

        Sample[] unDetectedDownloadedSamples = report.getUndetectedDownloadedSamples();
        if (unDetectedDownloadedSamples != null) {
            System.out.println("Undetected Downloaded Samples");
            for (Sample sample : unDetectedDownloadedSamples) {
                System.out.println("SHA256 : " + sample.getSha256());
                System.out.println("Date : " + sample.getDate());
                System.out.println("Positives : " + sample.getPositives());
                System.out.println("Total : " + sample.getTotal());

                assertNotNull(sample.getSha256());
                assertNotNull(sample.getDate());
                assertTrue(sample.getPositives() >= 0);
                assertTrue(sample.getTotal() > 0);
            }
        }

        Sample[] unDetectedCommunicatingSamples = report.getUndetectedCommunicatingSamples();
        if (unDetectedCommunicatingSamples != null) {
            System.out.println("Undetected Communicating Samples");
            for (Sample sample : unDetectedCommunicatingSamples) {
                System.out.println("SHA256 : " + sample.getSha256());
                System.out.println("Date : " + sample.getDate());
                System.out.println("Positives : " + sample.getPositives());
                System.out.println("Total : " + sample.getTotal());
            }
        }

        System.out.println("Response Code : " + report.getResponseCode());
        System.out.println("Verbose Message : " + report.getVerboseMessage());
    }

    @Test
    public void it_should_return_file_scan_report_when_resource_was_given()
            throws UnauthorizedAccessException, IOException,
            QuotaExceededException {
        String resource = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
        FileScanReport report = virusTotalRef.getScanReport(resource);

        System.out.println("MD5 :\t" + report.getMd5());
        System.out.println("Perma link :\t" + report.getPermalink());
        System.out.println("Resource :\t" + report.getResource());
        System.out.println("Scan Date :\t" + report.getScanDate());
        System.out.println("Scan Id :\t" + report.getScanId());
        System.out.println("SHA1 :\t" + report.getSha1());
        System.out.println("SHA256 :\t" + report.getSha256());
        System.out.println("Verbose Msg :\t" + report.getVerboseMessage());
        System.out.println("Response Code :\t" + report.getResponseCode());
        System.out.println("Positives :\t" + report.getPositives());
        System.out.println("Total :\t" + report.getTotal());

        assertNotNull(report.getMd5());
        assertNotNull(report.getPermalink());
        assertNotNull(report.getResource());
        assertNotNull(report.getScanDate());
        assertNotNull(report.getScanId());
        assertNotNull(report.getSha1());
        assertNotNull(report.getSha256());
        assertNotNull(report.getVerboseMessage());
        assertEquals(report.getResponseCode(), new Integer(1));
        assertTrue(report.getPositives() > 0);
        assertTrue(report.getTotal() > 0);

        Map<String, VirusScanInfo> scans = report.getScans();
        for (String key : scans.keySet()) {
            VirusScanInfo virusInfo = scans.get(key);
            System.out.println("Scanner : " + key);
            System.out.println("\t\t Resut : " + virusInfo.getResult());
            System.out.println("\t\t Update : " + virusInfo.getUpdate());
            System.out.println("\t\t Version :" + virusInfo.getVersion());
            assertNotNull(virusInfo);
            assertNotNull(virusInfo.getUpdate());
            assertNotNull(virusInfo.getVersion());
        }
    }


}
