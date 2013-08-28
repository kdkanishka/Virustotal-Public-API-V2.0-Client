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
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import java.io.File;
import java.io.UnsupportedEncodingException;

/**
 *
 * @author kdkanishka@gmail.com
 */
public interface VirustotalPublicV2 {

    final String URI_VT2_FILE_SCAN = "https://www.virustotal.com/vtapi/v2/file/scan";
    final String URI_VT2_RESCAN = "https://www.virustotal.com/vtapi/v2/file/rescan";
    final String URI_VT2_FILE_SCAN_REPORT = "https://www.virustotal.com/vtapi/v2/file/report";
    final String URI_VT2_URL_SCAN = "https://www.virustotal.com/vtapi/v2/url/scan";
    final String URI_VT2_URL_SCAN_REPORT = "http://www.virustotal.com/vtapi/v2/url/report";
    final String URI_VT2_IP_REPORT = "http://www.virustotal.com/vtapi/v2/ip-address/report";
    final String URI_VT2_DOMAIN_REPORT = "http://www.virustotal.com/vtapi/v2/domain/report";
    final String URI_VT2_PUT_COMMENT = "https://www.virustotal.com/vtapi/v2/comments/put";
    final String VT2_URLSEPERATOR = "\n";
    final int VT2_MAX_ALLOWED_URLS_PER_REQUEST = 4;

    /**
     *
     * @param fileToScan : the file object to be scanned
     * @return
     */
    ScanInfo scanFile(final File fileToScan) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception;

    /**
     *
     * @param resources : a set of md5/sha1/sha256 hashes. You can also specify
     * a CSV list made up of a combination of any of the three allowed hashes
     * (up to 25 items), this allows you to perform a batch request with one
     * single call. Note that the file must already be present in our file
     * store.
     * @return
     */
    ScanInfo[] reScanFiles(final String[] resources) throws UnsupportedEncodingException, UnauthorizedAccessException, InvalidArguentsException, Exception;

    /**
     *
     * @param resource : a md5/sha1/sha256 hash will retrieve the most recent
     * report on a given sample. You may also specify a scan_id
     * (sha256-timestamp as returned by the file upload API) to access a
     * specific report. You can also specify a CSV list made up of a combination
     * of hashes and scan_ids (up to 4 items with the standard request rate),
     * this allows you to perform a batch request with one single call.
     * @return
     */
    FileScanReport getScanReport(final String resource) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception;

    /**
     *
     * @param resources
     * @return
     */
    FileScanReport[] getScanReports(final String[] resources) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception;

    /**
     *
     * @param urls : set of urls to be scanned
     * @return
     */
    ScanInfo[] scanUrls(final String[] urls) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception;

    /**
     *
     * @param url : set of urls
     * @param scan : true if url s must be scanned before generating the report
     * @return
     */
    FileScanReport[] getUrlScanReport(final String[] url, boolean scan) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception;

    /**
     *
     * @param ipAddress
     * @return
     */
    IPAddressReport getIPAddresReport(final String ipAddress) throws InvalidArguentsException, Exception;

    /**
     *
     * @param domain : domain name
     * @return
     */
    DomainReport getDomainReport(final String domain) throws InvalidArguentsException, UnauthorizedAccessException, Exception;

    /**
     *
     * @param resource
     * @param comment
     * @return
     */
    GeneralResponse makeAComment(final String resource, final String comment);
}
