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
 - `mvn clean install`
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

##### Get file scan report
``` Java
    public static void getFileScanReport() {
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

[JDK 1.5 or higher version]:http://www.oracle.com/technetwork/java/javase/downloads/index.html
[Apache Maven 3.x]:http://maven.apache.org
