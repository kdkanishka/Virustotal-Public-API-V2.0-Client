Virustotal-Public-API-V2.0-Client
=================================


VirusTotal is a free service that analyzes suspicious files and URLs and facilitates the quick detection of viruses, worms, trojans, and all kinds of malware.

This is project is a VirusTotal public API version 2.0 implementation in Java.

Requirements
------------
- [JDK 1.5 or higher version]
- [Apache Maven 3.x]

Getting started
---------------
1. Clone project from GIT repo
 - `git clone https://github.com/kdkanishka/Virustotal-Public-API-V2.0-Client.git`
2. OR Download the project as a zip file and extract
 - `https://github.com/kdkanishka/Virustotal-Public-API-V2.0-Client/archive/master.zip`
3. Build and install the project using maven
 - `mvn clean install -DskipTests`
4. Add following dependency to your maven project

``` xml
<dependency>
      <groupId>com.kanishka.api</groupId>
      <artifactId>VirustotalPublicV2.0</artifactId>
      <version>1.0-SNAPSHOT</version>
</dependency>
```
* If your project is not maven based, add `target/VirustotalPublicV2.0-1.0-SNAPSHOT.jar` file to your class path.

How to use API
---------------------
### Sample codes
##### scan a given file

```Java
    public void scanFile() {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("APIKEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            ScanInfo scanInformation = virusTotalRef.scanFile(new File("/Users/kdesilva/Desktop/eicar.com.txt"));
            
            System.out.println("___SCAN INFORMATION___");
            System.out.println("MD5 :\t" + scanInformation.getMd5());
            System.out.println("Perma Link :\t" + scanInformation.getPermalink());
            System.out.println("Resource :\t" + scanInformation.getResource());
            System.out.println("Scan Date :\t" + scanInformation.getScan_date());
            System.out.println("Scan Id :\t" + scanInformation.getScan_id());
            System.out.println("SHA1 :\t" + scanInformation.getSha1());
            System.out.println("SHA256 :\t" + scanInformation.getSha256());
            System.out.println("Verbose Msg :\t" + scanInformation.getVerbose_msg());
            System.out.println("Response Code :\t" + scanInformation.getResponse_code());
            System.out.println("done.");
        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
```

##### Get File Scan Report
``` Java
    public void getFileScanReport() {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("APIKEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            String resource="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
            FileScanReport report = virusTotalRef.getScanReport(resource);

            System.out.println("MD5 :\t" + report.getMd5());
            System.out.println("Perma link :\t" + report.getPermalink());
            System.out.println("Resourve :\t" + report.getResource());
            System.out.println("Scan Date :\t" + report.getScan_date());
            System.out.println("Scan Id :\t" + report.getScan_id());
            System.out.println("SHA1 :\t" + report.getSha1());
            System.out.println("SHA256 :\t" + report.getSha256());
            System.out.println("Verbose Msg :\t" + report.getVerbose_msg());
            System.out.println("Response Code :\t" + report.getResponse_code());
            System.out.println("Positives :\t" + report.getPositives());
            System.out.println("Total :\t" + report.getTotal());

            HashMap<String, VirusScanInfo> scans = report.getScans();
            for (String key : scans.keySet()) {
                VirusScanInfo virusInfo = scans.get(key);
                System.out.println("Scanner : " + key);
                System.out.println("\t\t Resut : " + virusInfo.getResult());
                System.out.println("\t\t Update : " + virusInfo.getUpdate());
                System.out.println("\t\t Version :" + virusInfo.getVersion());
            }

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
```
##### Scan URL
``` Java
    public void scanUrl() {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("APIKEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            String urls[] = {"www.google.lk", "www.yahoo.com"};
            ScanInfo[] scanInfoArr = virusTotalRef.scanUrls(urls);

            for (ScanInfo scanInformation : scanInfoArr) {
                System.out.println("___SCAN INFORMATION___");
                System.out.println("MD5 :\t" + scanInformation.getMd5());
                System.out.println("Perma Link :\t" + scanInformation.getPermalink());
                System.out.println("Resource :\t" + scanInformation.getResource());
                System.out.println("Scan Date :\t" + scanInformation.getScan_date());
                System.out.println("Scan Id :\t" + scanInformation.getScan_id());
                System.out.println("SHA1 :\t" + scanInformation.getSha1());
                System.out.println("SHA256 :\t" + scanInformation.getSha256());
                System.out.println("Verbose Msg :\t" + scanInformation.getVerbose_msg());
                System.out.println("Response Code :\t" + scanInformation.getResponse_code());
                System.out.println("done.");
            }

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
```
##### Get URL Report
``` Java
    public void getUrlReport(){
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("APIKEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            String urls[] = {"mahamegha.com","mahamegha.info"};
            FileScanReport[] reports = virusTotalRef.getUrlScanReport(urls, false);

            for (FileScanReport report : reports) {
                if(report.getResponse_code()==0){
                    continue;
                }
                System.out.println("MD5 :\t" + report.getMd5());
                System.out.println("Perma link :\t" + report.getPermalink());
                System.out.println("Resourve :\t" + report.getResource());
                System.out.println("Scan Date :\t" + report.getScan_date());
                System.out.println("Scan Id :\t" + report.getScan_id());
                System.out.println("SHA1 :\t" + report.getSha1());
                System.out.println("SHA256 :\t" + report.getSha256());
                System.out.println("Verbose Msg :\t" + report.getVerbose_msg());
                System.out.println("Response Code :\t" + report.getResponse_code());
                System.out.println("Positives :\t" + report.getPositives());
                System.out.println("Total :\t" + report.getTotal());

                HashMap<String, VirusScanInfo> scans = report.getScans();
                for (String key : scans.keySet()) {
                    VirusScanInfo virusInfo = scans.get(key);
                    System.out.println("Scanner : " + key);
                    System.out.println("\t\t Resut : " + virusInfo.getResult());
                    System.out.println("\t\t Update : " + virusInfo.getUpdate());
                    System.out.println("\t\t Version :" + virusInfo.getVersion());
                }
            }

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
```
##### Get IP Address Report
``` Java
    public void getIPReport {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("APIKEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            IPAddressReport report = virusTotalRef.getIPAddresReport("69.195.124.58");

            System.out.println("___IP Rport__");

            Sample[] communicatingSamples = report.getDetected_communicating_samples();
            if (communicatingSamples != null) {
                System.out.println("Communicating Samples");
                for (Sample sample : communicatingSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            Sample[] detectedDownloadedSamples = report.getDetected_downloaded_samples();
            if (detectedDownloadedSamples != null) {
                System.out.println("Detected Downloaded Samples");
                for (Sample sample : detectedDownloadedSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            URL[] urls = report.getDetected_urls();
            if (urls != null) {
                System.out.println("Detected URLs");
                for (URL url : urls) {
                    System.out.println("URL : " + url.getUrl());
                    System.out.println("Positives : " + url.getPositives());
                    System.out.println("Total : " + url.getTotal());
                    System.out.println("Scan Date" + url.getScan_date());
                }
            }

            Resolution[] resolutions = report.getResolutions();
            if (resolutions != null) {
                System.out.println("Resolutions");
                for (Resolution resolution : resolutions) {
                    System.out.println("IP Address : " + resolution.getIp_address());
                    System.out.println("Last Resolved : " + resolution.getLast_resolved());
                }
            }

            Sample[] unDetectedDownloadedSamples = report.getUndetected_downloaded_samples();
            if (unDetectedDownloadedSamples != null) {
                System.out.println("Undetected Downloaded Samples");
                for (Sample sample : unDetectedDownloadedSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            Sample[] unDetectedCommunicatingSamples = report.getUndetected_communicating_samples();
            if (unDetectedCommunicatingSamples != null) {
                System.out.println("Undetected Communicating Samples");
                for (Sample sample : unDetectedCommunicatingSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            System.out.println("Response Code : " + report.getResponse_code());
            System.out.println("Verbose Message : " + report.getVerbose_msg());



        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
```
##### Get Domain Report
``` Java
    public void getDomainReport() {
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("APIKEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            DomainReport report = virusTotalRef.getDomainReport("www.ntt62.com");
            System.out.println("___Domain Rport__");

            Sample[] communicatingSamples = report.getDetected_communicating_samples();
            if (communicatingSamples != null) {
                System.out.println("Communicating Samples");
                for (Sample sample : communicatingSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            Sample[] detectedDownloadedSamples = report.getDetected_downloaded_samples();
            if (detectedDownloadedSamples != null) {
                System.out.println("Detected Downloaded Samples");
                for (Sample sample : detectedDownloadedSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            URL[] urls = report.getDetected_urls();
            if (urls != null) {
                System.out.println("Detected URLs");
                for (URL url : urls) {
                    System.out.println("URL : " + url.getUrl());
                    System.out.println("Positives : " + url.getPositives());
                    System.out.println("Total : " + url.getTotal());
                    System.out.println("Scan Date" + url.getScan_date());
                }
            }

            Resolution[] resolutions = report.getResolutions();
            if (resolutions != null) {
                System.out.println("Resolutions");
                for (Resolution resolution : resolutions) {
                    System.out.println("IP Address : " + resolution.getIp_address());
                    System.out.println("Last Resolved : " + resolution.getLast_resolved());
                }
            }

            Sample[] unDetectedDownloadedSamples = report.getUndetected_downloaded_samples();
            if (unDetectedDownloadedSamples != null) {
                System.out.println("Undetected Downloaded Samples");
                for (Sample sample : unDetectedDownloadedSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            Sample[] unDetectedCommunicatingSamples = report.getUndetected_communicating_samples();
            if (unDetectedCommunicatingSamples != null) {
                System.out.println("Undetected Communicating Samples");
                for (Sample sample : unDetectedCommunicatingSamples) {
                    System.out.println("SHA256 : " + sample.getSha256());
                    System.out.println("Date : " + sample.getDate());
                    System.out.println("Positives : " + sample.getPositives());
                    System.out.println("Total : " + sample.getTotal());
                }
            }

            System.out.println("Response Code : " + report.getResponse_code());
            System.out.println("Verbose Message : " + report.getVerbose_msg());



        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
```
#### Posting Comments
``` Java
    public void addComment(){
        try {
            VirusTotalConfig.getConfigInstance().setVirusTotalAPIKey("APIKEY");
            VirustotalPublicV2 virusTotalRef = new VirustotalPublicV2Impl();

            String resource = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f";
            String comment = "Eicar file! considered a goodware";
            GeneralResponse gRespo = virusTotalRef.makeAComment(resource, comment);

            System.out.println("Response Code : " + gRespo.getResponse_code());
            System.out.println("Verbose Message : " + gRespo.getVerbose_msg());

        } catch (APIKeyNotFoundException ex) {
            System.err.println("API Key not found! " + ex.getMessage());
        } catch (UnsupportedEncodingException ex) {
            System.err.println("Unsupported Encoding Format!" + ex.getMessage());
        } catch (UnauthorizedAccessException ex) {
            System.err.println("Invalid API Key " + ex.getMessage());
        } catch (Exception ex) {
            System.err.println("Something Bad Happened! " + ex.getMessage());
        }
    }
```
### Support or Contact
Having trouble with this api ? contact kdkanishka@gmail.com and I'll help you to sort it out.

### Contribute to this Project
You are welcome to suggest new features and improvements. please feel free to fork and make pull requests with your additions and improvements. 

[JDK 1.5 or higher version]:http://www.oracle.com/technetwork/java/javase/downloads/index.html
[Apache Maven 3.x]:http://maven.apache.org
