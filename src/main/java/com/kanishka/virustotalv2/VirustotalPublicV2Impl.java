/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package com.kanishka.virustotalv2;

import com.google.gson.Gson;
import com.kanishka.net.commons.BasicHTTPRequestImpl;
import com.kanishka.net.commons.HTTPRequest;
import com.kanishka.net.exception.RequestNotComplete;
import com.kanishka.net.model.MultiPartEntity;
import com.kanishka.net.model.RequestMethod;
import com.kanishka.net.model.Response;
import com.kanishka.virustotal.dto.DomainReport;
import com.kanishka.virustotal.dto.FileScanReport;
import com.kanishka.virustotal.dto.GeneralResponse;
import com.kanishka.virustotal.dto.IPAddressReport;
import com.kanishka.virustotal.dto.ScanInfo;
import com.kanishka.virustotal.exception.APIKeyNotFoundException;
import com.kanishka.virustotal.exception.InvalidArguentsException;
import com.kanishka.virustotal.exception.QuotaExceededException;
import com.kanishka.virustotal.exception.UnauthorizedAccessException;
import org.apache.http.entity.mime.content.FileBody;
import org.apache.http.entity.mime.content.StringBody;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

/**
 * @author kdkanishka@gmail.com
 */
public class VirustotalPublicV2Impl implements VirustotalPublicV2 {

    private Gson gsonProcessor;

    private String apiKey;

    private static final String API_KEY_FIELD = "apikey";

    private static final String RESOURCE_FIELD = "resource";

    private static final String ERR_MSG_EXCEED_MAX_REQ_PM = "Exceeded maximum" +
            " number of requests per minute, Please try again later.";

    private static final String ERR_MSG_INVALID_API_KEY = "Invalid api key";

    private static final String ERR_MSG_API_KEY_NOT_FOUND =
            "API Key is not set. Please set api key.\nSample :" +
                    " VirusTotalConfig.getConfigInstance()." +
                    "setVirusTotalAPIKey(\"APIKEY\")";

    private static final String ERR_MSG_FILE_NOT_FOUND =
            "Could not access file, either the file may not exists or not" +
                    " accessible!";

    private static final String ERR_MSG_INCORRECT_PARAM =
            "Incorrect parameter \'%s\', resource should be an array" +
                    " with at least one element";

    private static final String ERR_MSG2_INCORRECT_PARAM =
            "Incorrect parameter \'%s\' , " +
                    "maximum number(%d) of %s per request has been exceeded.";

    private static final String ERR_MSG3_INCORRECT_PARAM =
            "Incorrect parameter '%s', it should be a valid %s";

    private static final String ERR_COMMENTING = "Could not publish the " +
            "comment," +
            " API error occured!";

    public static final String URLS_LITERAL = "urls";

    private HTTPRequest httpRequestObject;

    public VirustotalPublicV2Impl() throws APIKeyNotFoundException {
        initialize();
        httpRequestObject = new BasicHTTPRequestImpl();
    }

    public VirustotalPublicV2Impl(String host, Integer port) throws APIKeyNotFoundException {
        initialize();
        httpRequestObject = new BasicHTTPRequestImpl(new InetSocketAddress(host, port));
    }

    public VirustotalPublicV2Impl(InetSocketAddress proxy) throws APIKeyNotFoundException {
        initialize();
        httpRequestObject = new BasicHTTPRequestImpl(proxy);
    }


    public VirustotalPublicV2Impl(HTTPRequest httpRequestObject) throws
            APIKeyNotFoundException {
        initialize();
        this.httpRequestObject = httpRequestObject;
    }

    private void initialize() throws APIKeyNotFoundException {
        gsonProcessor = new Gson();
        apiKey = VirusTotalConfig.getConfigInstance().getVirusTotalAPIKey();
        if (apiKey == null || apiKey.length() == 0) {
            throw new APIKeyNotFoundException(ERR_MSG_API_KEY_NOT_FOUND);
        }
    }

    @Override
    public ScanInfo scanFile(File fileToScan) throws
            IOException, UnauthorizedAccessException,
            QuotaExceededException {
        if (!fileToScan.canRead()) {
            throw new FileNotFoundException(ERR_MSG_FILE_NOT_FOUND);
        }
        Response responseWrapper = new Response();
        ScanInfo scanInfo = new ScanInfo();

        FileBody fileBody = new FileBody(fileToScan);
        MultiPartEntity file = new MultiPartEntity("file", fileBody);
        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD,
                new StringBody(apiKey));
        List<MultiPartEntity> multiParts = new ArrayList<MultiPartEntity>();
        multiParts.add(file);
        multiParts.add(apikey);
        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(URI_VT2_FILE_SCAN,
                    null, null, RequestMethod.GET, multiParts);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }
        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            scanInfo = gsonProcessor.fromJson(serviceResponse, ScanInfo.class);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }
        return scanInfo;

    }

    @Override
    public ScanInfo[] reScanFiles(String[] resources) throws
            IOException, UnauthorizedAccessException,
            InvalidArguentsException, QuotaExceededException {
        ScanInfo[] scanInfo = null;
        if (resources == null) {
            String errorMsg = String.format(ERR_MSG_INCORRECT_PARAM,
                    "resources");
            throw new InvalidArguentsException(errorMsg);
        }
        Response responseWrapper = new Response();

        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD,
                new StringBody(apiKey));
        StringBuilder resourceStr = new StringBuilder();
        for (String resource : resources) {
            resourceStr.append(resource).append(", ");
        }
        //clean up resource string
        int lastCommaIdx = resourceStr.lastIndexOf(",");
        if (lastCommaIdx > 0) {
            resourceStr.deleteCharAt(lastCommaIdx);
        }

        MultiPartEntity part = new MultiPartEntity(RESOURCE_FIELD,
                new StringBody(resourceStr.toString()));
        List<MultiPartEntity> multiParts = new ArrayList<MultiPartEntity>();
        multiParts.add(part);
        multiParts.add(apikey);
        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(URI_VT2_RESCAN,
                    null, null, RequestMethod.POST, multiParts);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }

        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            if (resources.length > 1) {
                scanInfo =
                        gsonProcessor.fromJson(serviceResponse,
                                ScanInfo[].class);
            } else {
                ScanInfo scanInfo1Elem = gsonProcessor.fromJson(serviceResponse,
                        ScanInfo.class);
                scanInfo = new ScanInfo[]{scanInfo1Elem};
            }
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }

        return scanInfo;
    }

    @Override
    public FileScanReport getScanReport(String resource)
            throws IOException, UnauthorizedAccessException,
            QuotaExceededException {
        Response responseWrapper = new Response();
        FileScanReport fileScanReport = new FileScanReport();

        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD,
                new StringBody(apiKey));
        MultiPartEntity resourcePart = new MultiPartEntity(RESOURCE_FIELD,
                new StringBody(resource));
        List<MultiPartEntity> multiParts = new ArrayList<MultiPartEntity>();
        multiParts.add(apikey);
        multiParts.add(resourcePart);
        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(URI_VT2_FILE_SCAN_REPORT
                    , null, null, RequestMethod.POST, multiParts);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }

        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            fileScanReport = gsonProcessor.fromJson(serviceResponse,
                    FileScanReport.class);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }
        return fileScanReport;
    }

    @Override
    public FileScanReport[] getScanReports(String[] resources) throws
            IOException, UnauthorizedAccessException,
            QuotaExceededException, InvalidArguentsException {
        Response responseWrapper = new Response();
        FileScanReport[] fileScanReport = null;
        if (resources == null) {
            String errorMsg = String.format(ERR_MSG_INCORRECT_PARAM,
                    "resources");
            throw new InvalidArguentsException(errorMsg);
        }

        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD,
                new StringBody(apiKey));
        StringBuilder resourceStr = new StringBuilder();
        for (String resource : resources) {
            resourceStr.append(resource).append(", ");
        }
        //clean up resource string
        int lastCommaIdx = resourceStr.lastIndexOf(",");
        if (lastCommaIdx > 0) {
            resourceStr.deleteCharAt(lastCommaIdx);
        }

        MultiPartEntity part = new MultiPartEntity(RESOURCE_FIELD,
                new StringBody(resourceStr.toString()));
        List<MultiPartEntity> multiParts = new ArrayList<MultiPartEntity>();
        multiParts.add(apikey);
        multiParts.add(part);
        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(URI_VT2_FILE_SCAN_REPORT
                    , null, null, RequestMethod.POST, multiParts);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }

        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            if (resources.length > 1) {
                fileScanReport = gsonProcessor.fromJson(serviceResponse,
                        FileScanReport[].class);
            } else {
                FileScanReport fScanRep =
                        gsonProcessor.fromJson(serviceResponse,
                                FileScanReport.class);
                fileScanReport = new FileScanReport[]{fScanRep};
            }
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }
        return fileScanReport;
    }

    @Override
    public ScanInfo[] scanUrls(String[] urls) throws IOException,
            UnauthorizedAccessException, QuotaExceededException,
            InvalidArguentsException {
        Response responseWrapper = new Response();
        ScanInfo[] scanInfo = null;
        if (urls == null) {
            String errorMsg = String.format(ERR_MSG_INCORRECT_PARAM, URLS_LITERAL);
            throw new InvalidArguentsException(errorMsg);
        } else if (urls.length > VT2_MAX_ALLOWED_URLS_PER_REQUEST) {
            String errMsg = String.format(ERR_MSG2_INCORRECT_PARAM, URLS_LITERAL,
                    VT2_MAX_ALLOWED_URLS_PER_REQUEST, URLS_LITERAL);
            throw new InvalidArguentsException(errMsg);
        }
        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD,
                new StringBody(apiKey));
        StringBuilder resourceStr = new StringBuilder();
        for (String url : urls) {
            resourceStr.append(url).append(VT2_URLSEPERATOR);
        }
        //clean up resource string
        int lastUrlSepIdx = resourceStr.lastIndexOf(VT2_URLSEPERATOR);
        if (lastUrlSepIdx > 0) {
            resourceStr.deleteCharAt(lastUrlSepIdx);
        }

        MultiPartEntity part = new MultiPartEntity("url",
                new StringBody(resourceStr.toString()));
        List<MultiPartEntity> multiParts = new ArrayList<MultiPartEntity>();
        multiParts.add(apikey);
        multiParts.add(part);
        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(URI_VT2_URL_SCAN, null,
                    null, RequestMethod.POST, multiParts);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }

        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            if (urls.length > 1) {
                scanInfo = gsonProcessor.fromJson(serviceResponse,
                        ScanInfo[].class);
            } else {
                ScanInfo scanInforElem = gsonProcessor.fromJson(serviceResponse,
                        ScanInfo.class);
                scanInfo = new ScanInfo[]{scanInforElem};
            }
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }
        return scanInfo;
    }

    @Override
    public FileScanReport[] getUrlScanReport(String[] urls, boolean scan) throws
            IOException, UnauthorizedAccessException,
            QuotaExceededException, InvalidArguentsException {
        Response responseWrapper = new Response();
        FileScanReport[] fileScanReport = null;
        if (urls == null) {
            String errMsg = String.format(ERR_MSG_INCORRECT_PARAM, "resources");
            throw new InvalidArguentsException(errMsg);
        } else if (urls.length > VT2_MAX_ALLOWED_URLS_PER_REQUEST) {
            String errMsg = String.format(ERR_MSG2_INCORRECT_PARAM,
                    "urls", VT2_MAX_ALLOWED_URLS_PER_REQUEST, "urls");
            throw new InvalidArguentsException(errMsg);
        }

        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD,
                new StringBody(apiKey));
        StringBuilder resourceStr = new StringBuilder();
        for (String resource : urls) {
            resourceStr.append(resource).append("\n");
        }
        //clean up resource string
        int lastCommaIdx = resourceStr.lastIndexOf("\n");
        if (lastCommaIdx > 0) {
            resourceStr.deleteCharAt(lastCommaIdx);
        }

        MultiPartEntity part = new MultiPartEntity(RESOURCE_FIELD,
                new StringBody(resourceStr.toString()));
        List<MultiPartEntity> multiParts = new ArrayList<MultiPartEntity>();
        multiParts.add(apikey);
        multiParts.add(part);

        if (scan) {
            MultiPartEntity scanPart =
                    new MultiPartEntity("scan", new StringBody("1"));
            multiParts.add(scanPart);
        }
        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(URI_VT2_URL_SCAN_REPORT,
                    null, null, RequestMethod.POST, multiParts);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }

        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            if (urls.length > 1) {
                fileScanReport = gsonProcessor.fromJson(serviceResponse,
                        FileScanReport[].class);
            } else {
                FileScanReport fileScanReportElem =
                        gsonProcessor.fromJson(serviceResponse,
                                FileScanReport.class);
                fileScanReport = new FileScanReport[]{fileScanReportElem};
            }
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }
        return fileScanReport;
    }

    @Override
    public IPAddressReport getIPAddresReport(String ipAddress) throws
            InvalidArguentsException, QuotaExceededException,
            UnauthorizedAccessException, IOException {
        Response responseWrapper = new Response();
        IPAddressReport ipReport = new IPAddressReport();
        if (ipAddress == null) {
            String errMsg = String.format(ERR_MSG3_INCORRECT_PARAM,
                    "ipAddress", "IP address");
            throw new InvalidArguentsException(errMsg);
        }

        String uriWithParams = URI_VT2_IP_REPORT + "?apikey=" + apiKey + "&ip="
                + ipAddress;
        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(uriWithParams, null,
                    null, RequestMethod.GET, null);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }

        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            ipReport = gsonProcessor.fromJson(serviceResponse,
                    IPAddressReport.class);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }
        return ipReport;
    }

    @Override
    public DomainReport getDomainReport(String domain) throws
            InvalidArguentsException, UnauthorizedAccessException,
            QuotaExceededException, IOException {
        Response responseWrapper = new Response();
        DomainReport domainReport = new DomainReport();
        if (domain == null) {
            String errMsg = String.format(ERR_MSG3_INCORRECT_PARAM, "domain",
                    "domain name");
            throw new InvalidArguentsException(errMsg);
        }

        String uriWithParams = URI_VT2_DOMAIN_REPORT + "?apikey=" +
                apiKey + "&domain=" + domain;
        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(uriWithParams, null,
                    null, RequestMethod.GET, null);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }

        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            domainReport = gsonProcessor.fromJson(serviceResponse,
                    DomainReport.class);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }
        return domainReport;
    }

    @Override
    public GeneralResponse makeAComment(String resource, String comment) throws
            IOException, UnauthorizedAccessException,
            InvalidArguentsException, QuotaExceededException {
        if (resource == null || resource.length() == 0) {
            String errMsg = String.format(ERR_MSG3_INCORRECT_PARAM,
                    "resource", "string representing a hash value (md2,sha1," +
                    "sha256)");
            throw new InvalidArguentsException(errMsg);
        }
        Response responseWrapper = new Response();

        GeneralResponse generalResponse = new GeneralResponse();
        generalResponse.setResponseCode(-1);
        generalResponse.setVerboseMessage(ERR_COMMENTING);

        MultiPartEntity apikey = new MultiPartEntity(API_KEY_FIELD,
                new StringBody(apiKey));
        MultiPartEntity resourcePart = new MultiPartEntity(RESOURCE_FIELD,
                new StringBody(resource));
        MultiPartEntity commentPart = new MultiPartEntity("comment",
                new StringBody(comment));
        List<MultiPartEntity> multiParts = new ArrayList<MultiPartEntity>();
        multiParts.add(apikey);
        multiParts.add(resourcePart);
        multiParts.add(commentPart);

        Integer statusCode = -1;

        try {
            responseWrapper = httpRequestObject.request(URI_VT2_PUT_COMMENT,
                    null, null, RequestMethod.POST, multiParts);
            statusCode = responseWrapper.getStatus();
        } catch (RequestNotComplete e) {
            statusCode = e.getHttpStatus().getStatusCode();
            if (statusCode == VirustotalStatus.FORBIDDEN) {
                //fobidden
                throw new UnauthorizedAccessException(ERR_MSG_INVALID_API_KEY,
                        e);
            }
        }

        if (statusCode == VirustotalStatus.SUCCESSFUL) {
            //valid response
            String serviceResponse = responseWrapper.getResponse();
            generalResponse = gsonProcessor.fromJson(serviceResponse,
                    GeneralResponse.class);
        } else if (statusCode == VirustotalStatus.API_LIMIT_EXCEEDED) {
            //limit exceeded
            throw new QuotaExceededException(ERR_MSG_EXCEED_MAX_REQ_PM);
        }
        return generalResponse;
    }
}
