/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import com.google.gson.Gson;
import com.kanishka.net.commons.BasicHTTPRequestImpl;
import com.kanishka.net.commons.HTTPRequest;
import com.kanishka.net.model.MultiPartEntity;
import com.kanishka.net.model.RequestMethod;
import com.kanishka.virustotal.dto.DomainReport;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.GeneralResponse;
import com.kanishka.virustotal.dto.IPAddressReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.InvalidArguentsException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import static com.kanishka.virustotalv2.VirustotalPublicV2.URI_VT2_DOMAIN_REPORT;
import static com.kanishka.virustotalv2.VirustotalPublicV2.URI_VT2_FILE_SCAN;
import static com.kanishka.virustotalv2.VirustotalPublicV2.URI_VT2_FILE_SCAN_REPORT;
import static com.kanishka.virustotalv2.VirustotalPublicV2.URI_VT2_RESCAN;
import static com.kanishka.virustotalv2.VirustotalPublicV2.VT2_MAX_ALLOWED_URLS_PER_REQUEST;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;

/**
 *
 * @author kdkanishka@gmail.com
 */
public class VirustotalPublicV2Impl implements VirustotalPublicV2 {

    private Gson gsonProcessor;
    private String apiKey;
    private static final String API_KEY_FIELD = "apikey";
    private static final String RESOURCE_FIELD = "resource";
    private static final String ERR_MSG_EXCEED_MAX_REQ_PM = "Exceeded maximum number of requests per minute, Please try again later.";
    private static final String ERR_MSG_INVALID_API_KEY = "Invalid api key";

    public VirustotalPublicV2Impl() throws APIKeyNotFoundException {
        gsonProcessor = new Gson();
        apiKey = VirusTotalConfig.getConfigInstance().getVirusTotalAPIKey();
        if (apiKey == null || apiKey.length() == 0) {
            throw new APIKeyNotFoundException("API Key is not set. Please set api key.\nSample : VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey(\"APIKEY\")");
        } else {
            this.apiKey = apiKey;
        }
    }

    @Override
    public ScanInfo scanFile(File fileToScan) throws UnsupportedEncodingException, UnauthorizedAccessException, FileNotFoundException, Exception {
        if(!fileToScan.canRead()){
            throw new FileNotFoundException("Could not access file, either the file may not exists or not accessible!");
        }
        ScanInfo scanInfo = new ScanInfo();
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.POST);
        FileBody fileBody = new FileBody(fileToScan);
        MultiPartEntity file = new MultiPartEntity("file", fileBody);
        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD, new StringBody(apiKey));
        req.addPart(file);
        req.addPart(apikey);
        req.request(URI_VT2_FILE_SCAN);
        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            scanInfo = gsonProcessor.fromJson(serviceResponse, ScanInfo.class);
        }
        return scanInfo;
    }

    @Override
    public ScanInfo[] reScanFiles(String[] resources) throws UnsupportedEncodingException, UnauthorizedAccessException, InvalidArguentsException, Exception {
        ScanInfo[] scanInfo = null;
        if (resources == null) {
            throw new InvalidArguentsException("Incorrect parameter \'resources\', resource should be an array with at least one element");
        }
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.POST);
        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD, new StringBody(apiKey));
        req.addPart(apikey);
        StringBuilder resourceStr = new StringBuilder();
        for (String resource : resources) {
            resourceStr.append(resource).append(", ");
        }
        //clean up resource string
        int lastCommaIdx = resourceStr.lastIndexOf(",");
        if (lastCommaIdx > 0) {
            resourceStr.deleteCharAt(lastCommaIdx);
        }

        MultiPartEntity part = new MultiPartEntity(RESOURCE_FIELD, new StringBody(resourceStr.toString()));
        req.addPart(part);
        req.request(URI_VT2_RESCAN);
        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            scanInfo = gsonProcessor.fromJson(serviceResponse, ScanInfo[].class);
        }
        return scanInfo;
    }

    @Override
    public FileScanReport getScanReport(String resource) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception {
        FileScanReport fileScanReport = new FileScanReport();
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.POST);
        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD, new StringBody(apiKey));
        MultiPartEntity resourcePart = new MultiPartEntity(RESOURCE_FIELD, new StringBody(resource));
        req.addPart(apikey);
        req.addPart(resourcePart);
        req.request(URI_VT2_FILE_SCAN_REPORT);
        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            fileScanReport = gsonProcessor.fromJson(serviceResponse, FileScanReport.class);
        }
        return fileScanReport;
    }

    @Override
    public FileScanReport[] getScanReports(String[] resources) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception {
        FileScanReport[] fileScanReport = null;
        if (resources == null) {
            throw new InvalidArguentsException("Incorrect parameter \'resources\', resource should be an array with at least one element");
        }
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.POST);
        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD, new StringBody(apiKey));
        req.addPart(apikey);
        StringBuilder resourceStr = new StringBuilder();
        for (String resource : resources) {
            resourceStr.append(resource).append(", ");
        }
        //clean up resource string
        int lastCommaIdx = resourceStr.lastIndexOf(",");
        if (lastCommaIdx > 0) {
            resourceStr.deleteCharAt(lastCommaIdx);
        }

        MultiPartEntity part = new MultiPartEntity(RESOURCE_FIELD, new StringBody(resourceStr.toString()));
        req.addPart(part);
        req.request(URI_VT2_FILE_SCAN_REPORT);
        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            fileScanReport = gsonProcessor.fromJson(serviceResponse, FileScanReport[].class);
        }
        return fileScanReport;
    }

    @Override
    public ScanInfo[] scanUrls(String[] urls) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception {
        ScanInfo[] scanInfo = null;
        if (urls == null) {
            throw new InvalidArguentsException("Incorrect parameter \'urls\' , urls should be an array with at least one element ");
        } else if (urls.length > VT2_MAX_ALLOWED_URLS_PER_REQUEST) {
            throw new InvalidArguentsException("Incorrect parameter \'urls\' , maximum number(" + VT2_MAX_ALLOWED_URLS_PER_REQUEST + ") of urls per request has been exceeded.");
        }
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.POST);
        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD, new StringBody(apiKey));
        req.addPart(apikey);
        StringBuilder resourceStr = new StringBuilder();
        for (String url : urls) {
            resourceStr.append(url).append(VT2_URLSEPERATOR);
        }
        //clean up resource string
        int lastUrlSepIdx = resourceStr.lastIndexOf(VT2_URLSEPERATOR);
        if (lastUrlSepIdx > 0) {
            resourceStr.deleteCharAt(lastUrlSepIdx);
        }

        MultiPartEntity part = new MultiPartEntity("url", new StringBody(resourceStr.toString()));
        req.addPart(part);
        req.request(URI_VT2_URL_SCAN);
        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            scanInfo = gsonProcessor.fromJson(serviceResponse, ScanInfo[].class);
        }
        return scanInfo;
    }

    @Override
    public FileScanReport[] getUrlScanReport(String[] urls, boolean scan) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception {
        FileScanReport[] fileScanReport = null;
        if (urls == null) {
            throw new InvalidArguentsException("Incorrect parameter \'resources\', resource should be an array with at least one element");
        } else if (urls.length > VT2_MAX_ALLOWED_URLS_PER_REQUEST) {
            throw new InvalidArguentsException("Incorrect parameter \'urls\' , maximum number(" + VT2_MAX_ALLOWED_URLS_PER_REQUEST + ") of urls per request has been exceeded.");
        }
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.POST);
        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD, new StringBody(apiKey));
        req.addPart(apikey);
        StringBuilder resourceStr = new StringBuilder();
        for (String resource : urls) {
            resourceStr.append(resource).append(", ");
        }
        //clean up resource string
        int lastCommaIdx = resourceStr.lastIndexOf(",");
        if (lastCommaIdx > 0) {
            resourceStr.deleteCharAt(lastCommaIdx);
        }

        MultiPartEntity part = new MultiPartEntity(RESOURCE_FIELD, new StringBody(resourceStr.toString()));
        req.addPart(part);
        if (scan) {
            MultiPartEntity scanPart = new MultiPartEntity("scan", new StringBody("1"));
            req.addPart(scanPart);
        }
        req.request(URI_VT2_URL_SCAN_REPORT);
        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            fileScanReport = gsonProcessor.fromJson(serviceResponse, FileScanReport[].class);
        }
        return fileScanReport;
    }

    @Override
    public IPAddressReport getIPAddresReport(String ipAddress) throws InvalidArguentsException, Exception {
        IPAddressReport ipReport = new IPAddressReport();
        if (ipAddress == null) {
            throw new InvalidArguentsException("Incorrect parameter \'ipAddress\', it should be a valid IP address ");
        }
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.GET);
        String uriWithParams = URI_VT2_IP_REPORT + "?apikey=" + apiKey + "&ip=" + ipAddress;
        req.request(uriWithParams);
        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            ipReport = gsonProcessor.fromJson(serviceResponse, IPAddressReport.class);
        }
        return ipReport;
    }

    @Override
    public DomainReport getDomainReport(String domain) throws InvalidArguentsException, Exception {
        DomainReport domainReport = new DomainReport();
        if (domain == null) {
            throw new InvalidArguentsException("Incorrect parameter \'domain\', it should be a valid domain name");
        }
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.GET);
        String uriWithParams = URI_VT2_DOMAIN_REPORT + "?apikey=" + apiKey + "&domain=" + domain;
        req.request(uriWithParams);

        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            domainReport = gsonProcessor.fromJson(serviceResponse, DomainReport.class);
        }
        return domainReport;
    }

    @Override
    public GeneralResponse makeAComment(String resource, String comment) throws UnsupportedEncodingException, UnauthorizedAccessException, Exception {
        if (resource == null || resource.length() == 0) {
            throw new InvalidArguentsException("Incorrect parameter \'resource\', it should be a string representing a hash value (md2,sha1,sha256)");
        }
        GeneralResponse generalResponse = new GeneralResponse();
        generalResponse.setResponse_code(-1);
        generalResponse.setVerbose_msg("Could not publish the comment, API error occured!");
        HTTPRequest req = new BasicHTTPRequestImpl();
        req.setMethod(RequestMethod.POST);

        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD, new StringBody(apiKey));
        MultiPartEntity resourcePart = new MultiPartEntity(RESOURCE_FIELD, new StringBody(resource));
        MultiPartEntity commentPart = new MultiPartEntity("comment", new StringBody(comment));
        req.addPart(apikey);
        req.addPart(resourcePart);
        req.addPart(commentPart);
        req.request(URI_VT2_PUT_COMMENT);
        int statusCode = req.getStatus();
        if (statusCode == VirustotalStatus.FORBIDDEN) {
            //fobidden
            throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        } else if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = req.getResponse();
            generalResponse = gsonProcessor.fromJson(serviceResponse, GeneralResponse.class);
        }
        return generalResponse;
    }
}
