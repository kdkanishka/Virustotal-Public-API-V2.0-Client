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



[JDK 1.5 or higher version]:http://www.oracle.com/technetwork/java/javase/downloads/index.html
[Apache Maven 3.x]:http://maven.apache.org
