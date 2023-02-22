# Changelog
All notable changes to these images will be documented in this file.

## [1.0.12] - 2023-02-22
* Updates to to resolve https://github.com/a23au/awe-base-images/issues/23 for the following CVEs:

 * CVE-2023-23914
 * CVE-2023-23915
 * CVE-2022-4203
 * CVE-2022-4304
 * CVE-2023-23916
 * CVE-2022-4450
 * CVE-2023-0215
 * CVE-2023-0216
 * CVE-2023-0217
 * CVE-2023-0401
 * CVE-2022-24963
 * CVE-2022-28331
 * CVE-2022-25147
 * CVE-2023-0286

## [1.0.11] - 2023-01-23
* Updates to libcurl and krb5-libs on alpine based images to resolve following CVEs:

#### Vulnerability CVE-2022-42898

| Severity |	Package |	Fixed Version |	Link |
| ------------- | ------------- | ------------- | ------------- |
| HIGH |	krb5-libs |	1.19.4-r0 |	[CVE-2022-42898](https://avd.aquasec.com/nvd/cve-2022-42898) |

PAC parsing in MIT Kerberos 5 (aka krb5) before 1.19.4 and 1.20.x before 1.20.1 has integer overflows that may lead to remote code execution (in KDC, kadmind, or a GSS or Kerberos application server) on 32-bit platforms (which have a resultant heap-based buffer overflow), and cause a denial of service on other platforms. This occurs in krb5_pac_parse in lib/krb5/krb/pac.c. Heimdal before 7.7.1 has "a similar bug."

#### Vulnerability CVE-2022-43551

| Severity |	Package |	Fixed Version |	Link |
| ------------- | ------------- | ------------- | ------------- |
| HIGH |	libcurl |	7.83.1-r5 |	[CVE-2022-43551](https://avd.aquasec.com/nvd/cve-2022-43551) |

A vulnerability exists in curl <7.87.0 HSTS check that could be bypassed to trick it to keep using HTTP. Using its HSTS support, curl can be instructed to use HTTPS instead of using an insecure clear-text HTTP step even when HTTP is provided in the URL. However, the HSTS mechanism could be bypassed if the host name in the given URL first uses IDN characters that get replaced to ASCII counterparts as part of the IDN conversion. Like using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop (U+002E) .. Then in a subsequent request, it does not detect the HSTS state and makes a clear text transfer. Because it would store the info IDN encoded but look for it IDN decoded.


#### Vulnerability CVE-2022-43552

| Severity |	Package |	Fixed Version |	Link |
| ------------- | ------------- | ------------- | ------------- |
| MEDIUM |	libcurl |	7.83.1-r5	| [CVE-2022-43552](https://avd.aquasec.com/nvd/cve-2022-43552) |

A vulnerability was found in curl. In this issue, curl can be asked to tunnel all protocols virtually it supports through an HTTP proxy. HTTP proxies can deny these tunnel operations using an appropriate HTTP error response code. When getting denied to tunnel the specific SMB or TELNET protocols, curl can use a heap-allocated struct after it has been freed and shut down the code path in its transfer.


## [1.0.10] - 2022-11-11
* Remove the following from Corretto Dockerfile:
  * RUN mkdir -p /usr/local/tomcat/conf/Catalina/localhost
  * RUN chmod -R a+rwx /usr/local/tomcat/conf/Catalina

## [1.0.9] - 2022-11-11
* Added 2 tomcat conf folders

Updates to libcurl and expat on httpd based alpine images (all but awe-tomcat-jdk7-corretto) to resolve following CVEs:
#### CVE-2022-32221

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |
| MEDIUM | libcurl | 7.83.1-r4 | [CVE-2022-32221](https://avd.aquasec.com/nvd/cve-2022-32221) |

A vulnerability was found in curl. The issue occurs when doing HTTP(S) transfers, where curl might erroneously use the read callback (CURLOPT_READFUNCTION) to ask for data to send, even when the CURLOPT_POSTFIELDS option has been set if it previously used the same handle to issue a PUT request which used that callback. This flaw may surprise the application and cause it to misbehave and either send off the wrong data or use memory after free or similar in the subsequent POST request.

#### CVE-2022-42916

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |
| HIGH | libcurl | 7.83.1-r4 | [CVE-2022-42916](https://avd.aquasec.com/nvd/2022/cve-2022-42916/) |

In curl before 7.86.0, the HSTS check could be bypassed to trick it into staying with HTTP. Using its HSTS support, curl can be instructed to use HTTPS directly (instead of using an insecure cleartext HTTP step) even when HTTP is provided in the URL. This mechanism could be bypassed if the host name in the given URL uses IDN characters that get replaced with ASCII counterparts as part of the IDN conversion, e.g., using the character UTF-8 U+3002 (IDEOGRAPHIC FULL STOP) instead of the common ASCII full stop of U+002E (.). The earliest affected version is 7.77.0 2021-05-26.

#### CVE-2022-42915

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |
| CRITICAL | libcurl | 7.83.1-r4 | [CVE-2022-42915](https://avd.aquasec.com/nvd/2022/cve-2022-42915/) |

curl before 7.86.0 has a double free. If curl is told to use an HTTP proxy for a transfer with a non-HTTP(S) URL, it sets up the connection to the remote server by issuing a CONNECT request to the proxy, and then tunnels the rest of the protocol through. An HTTP proxy might refuse this request (HTTP proxies often only allow outgoing connections to specific port numbers, like 443 for HTTPS) and instead return a non-200 status code to the client. Due to flaws in the error/cleanup handling, this could trigger a double free in curl if one of the following schemes were used in the URL for the transfer: dict, gopher, gophers, ldap, ldaps, rtmp, rtmps, or telnet. The earliest affected version is 7.77.0.

#### CVE-2022-43680

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |
| HIGH | expat | 2.5.0-r0 | [CVE-2022-43680](https://avd.aquasec.com/nvd/2022/cve-2022-43680/) |

In libexpat through 2.4.9, there is a use-after free caused by overeager destruction of a shared DTD in XML_ExternalEntityParserCreate in out-of-memory situations.


## [1.0.8] - 2022-10-20
### awe-perl-base
Performing the following updates:
* (1/11) Upgrading expat (2.4.8-r0 -> 2.4.9-r0)
* (2/11) Upgrading busybox (1.35.0-r14 -> 1.35.0-r17)
* (3/11) Upgrading ca-certificates (20211220-r0 -> 20220614-r0)
* (4/11) Upgrading ssl_client (1.35.0-r14 -> 1.35.0-r17)
* (5/11) Upgrading zlib (1.2.12-r1 -> 1.2.12-r3)
* (6/11) Upgrading libcurl (7.83.1-r2 -> 7.83.1-r3)
* (7/11) Upgrading libldap (2.6.2-r0 -> 2.6.3-r1)
* (8/11) Upgrading libxml2 (2.9.14-r0 -> 2.9.14-r2)
* (9/11) Upgrading alpine-baselayout-data (3.2.0-r22 -> 3.2.0-r23)
* (10/11) Upgrading alpine-baselayout (3.2.0-r22 -> 3.2.0-r23)
* (11/11) Upgrading ca-certificates-bundle (20211220-r0 -> 20220614-r0)

...to resolve CVEs:

#### CVE-2022-37434

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |
|CRITICAL | zlib | 1.2.12-r2 | [CVE-2022-37434](https://avd.aquasec.com/nvd/cve-2022-37434)

zlib through 1.2.12 has a heap-based buffer over-read or buffer overflow in inflate in inflate.c via a large gzip header extra field. NOTE: only applications that call inflateGetHeader are affected. Some common applications bundle the affected zlib source code but may be unable to call inflateGetHeader (e.g., see the nodejs/node reference).
#### CVE-2021-46828

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |
|HIGH | libtirpc-conf | 1.3.2-r1 | [CVE-2021-46828](https://avd.aquasec.com/nvd/cve-2021-46828) |

In libtirpc before 1.3.3rc1, remote attackers could exhaust the file descriptors of a process that uses libtirpc because idle TCP connections are mishandled. This can, in turn, lead to an svc_run infinite loop without accepting new connections.

#### CVE-2022-30065

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |
| HIGH | ssl_client | 1.35.0-r15 | [CVE-2022-30065](https://avd.aquasec.com/nvd/cve-2022-30065) |

A use-after-free in Busybox 1.35-x's awk applet leads to denial of service and possibly code execution when processing a crafted awk pattern in the copyvar function.

#### CVE-2022-35252

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |

| LOW | libcurl | 7.83.1-r3 | [CVE-2022-35252](https://avd.aquasec.com/nvd/cve-2022-35252) |
No description is available for this CVE.

#### CVE-2022-3209

| Severity | Package | Fixed Version | Link |
| ------------- | ------------- | ------------- | ------------- |
| UNKNOWN | libxml2 | 2.9.14-r1	| N/A |


## [1.0.7] - 2022-07-13
### awe-perl-base
- Add `cpan install HTML::Template::Expr`

## [1.0.6] - 2022-07-06
### awe-tomcat-jdk7-corretto
- Changed base Tomcat image to 8.5-jdk8-corretto

## [1.0.5] - 2022-06-17
### awe-httpd-base
- Update `awe-httpd-base` base image to `2.4.54-alpine`

This is to resolve the following CVE
| Severity                                                                                                                 | Priority Score / 1000  | Issue                                                                     | Exploit Maturity      |
| :------:                                                                                                                 | :--------------------  | :----                                                                     | :---------------      |
| ![high severity](https://res.cloudinary.com/snyk/image/upload/w_20,h_20/v1561977819/icon/h.png "high severity")   | **471**  | Out-of-bounds Read <br/>[SNYK-ALPINE316-APR-2849152](https://snyk.io/vuln/SNYK-ALPINE316-APR-2849152)   | No Known Exploit   |

## [1.0.4] - 2022-06-01
### awe-perl-base
- Added install of perl-html-template and Tie::IxHash
  - Found to be required by (at least) AHPL
### awe-perl-oracle
- Removed instantclient-sqlplus-linux.x64-21.6.0.0.0dbru.zip from install as it is not required

## [1.0.3] - 2022-06-01
- Rebuild awe-httpd-base to resolve [CVE-2021-35940](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-35940)
  - Rebuild of all images relying on awe-httpd-base

## [1.0.2] - 2022-05-26
- Moved to using Alpine base images for awe-perl-* and awe-httpd-base images
