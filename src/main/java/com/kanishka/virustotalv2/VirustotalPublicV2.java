/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import com.kanishka.virustotal.dto.DomainReport;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.GeneralResponse;
import com.kanishka.virustotal.dto.IPAddressReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.InvalidArguentsException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;

import java.io.File;
import java.io.IOException;

/**
 * @author kdkanishka@gmail.com
 */
public interface VirustotalPublicV2 {

    String URI_VT2_FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/scan";
    String URI_VT2_RESCAN = "https://www.virustotal.com/vtapi/v2/file/rescan";
    String URI_VT2_FILE_SCAN_REPORT = "https://www.virustotal.com/vtapi/v2/file/report";
    String URI_VT2_URL_SCAN = "https://www.virustotal.com/vtapi/v2/url/scan";
    String URI_VT2_URL_SCAN_REPORT = "http://www.virustotal.com/vtapi/v2/url/report";
    String URI_VT2_IP_REPORT = "http://www.virustotal.com/vtapi/v2/ip-address/report";
    String URI_VT2_DOMAIN_REPORT = "http://www.virustotal.com/vtapi/v2/domain/report";
    String URI_VT2_PUT_COMMENT = "https://www.virustotal.com/vtapi/v2/comments/put";
    String VT2_URLSEPERATOR = "\n";
    int VT2_MAX_ALLOWED_URLS_PER_REQUEST = 4;

    /**
     * Scan a given single file
     *
     * @param fileToScan the file object to be scanned
     * @return scan information
     */
    ScanInfo scanFile(final File fileToScan) throws IOException, UnauthorizedAccessException, QuotaExceededException;

    /**
     * The call allows you to rescan files in VirusTotal's file store without having to resubmit them, thus saving bandwidth.
     * <p/>
     * The VirusTotal public API allows you to rescan files that you or other users already sent in the past and, hence,
     * are already present in our file store. Before requesting a rescan we encourage you to retrieve the latest report
     * on the files, if it is recent enough you might want to save time and bandwidth by making use of it.
     *
     * @param resources a set of md5/sha1/sha256 hashes.this allows you to perform a batch request with one
     *                  single call. Note that the file must already be present in our file
     *                  store.
     * @return
     */
    ScanInfo[] reScanFiles(final String[] resources) throws IOException, UnauthorizedAccessException, InvalidArguentsException, QuotaExceededException;

    /**
     * Returns the detailed most reason scan report for a given resource
     *
     * @param resource a md5/sha1/sha256 hash will retrieve the most recent
     *                 report on a given sample. You may also specify a scan_id
     *                 (sha256-timestamp as returned by the file upload API) to access a
     *                 specific report.
     * @return
     */
    FileScanReport getScanReport(final String resource) throws IOException, UnauthorizedAccessException, QuotaExceededException;

    /**
     * Returns the detailed most reason scan reports for given set of resources
     *
     * @param resources You can also specify an array of resources (up to 4 items with the standard request rate),
     *                  this allows you to perform a batch request with one single call.
     * @return
     */
    FileScanReport[] getScanReports(final String[] resources) throws IOException, UnauthorizedAccessException, QuotaExceededException, InvalidArguentsException;

    /**
     * URLs can also be submitted for scanning. Once again, before performing your submission we encourage you to retrieve
     * the latest report on the URL, if it is recent enough you might want to save time and bandwidth by making use of it.
     *
     * @param urls set of urls to be scanned
     * @return
     */
    ScanInfo[] scanUrls(final String[] urls) throws IOException, UnauthorizedAccessException, QuotaExceededException, InvalidArguentsException;

    /**
     * Returns the detailed scan report for given set of urls
     *
     * @param url  set of urls
     * @param scan true if url s must be scanned before generating the report
     * @return
     */
    FileScanReport[] getUrlScanReport(final String[] url, boolean scan) throws IOException, UnauthorizedAccessException, QuotaExceededException, InvalidArguentsException;

    /**
     * Returns detailed report for a given IP
     *
     * @param ipAddress a valid IPv4 address in dotted quad notation, for the time being only IPv4 addresses are supported.
     * @return
     */
    IPAddressReport getIPAddresReport(final String ipAddress) throws InvalidArguentsException, QuotaExceededException, UnauthorizedAccessException, IOException;

    /**
     * Returns a detailed report for a given domain
     *
     * @param domain domain name
     * @return
     */
    DomainReport getDomainReport(final String domain) throws InvalidArguentsException, UnauthorizedAccessException, QuotaExceededException, IOException;

    /**
     * @param resource either a md5/sha1/sha256 hash of the file you want to review or the URL itself that you want to comment on.
     * @param comment  the actual review, you can tag it using the "#" twitter-like syntax (e.g. #disinfection #zbot)
     *                 and reference users using the "@" syntax (e.g. @VirusTotalTeam).
     * @return
     */
    GeneralResponse makeAComment(final String resource, final String comment) throws IOException, UnauthorizedAccessException, InvalidArguentsException, QuotaExceededException;
}
