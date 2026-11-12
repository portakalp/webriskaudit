# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 2 |
| Low | 0 |
| Informational | 1 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP errors logged - see the zap.log file for details | 20    |
| Low | Warning |  | ZAP warnings logged - see the zap.log file for details | 3    |
| Info | Informational |  | Percentage of network failures | 47 % |
| Info | Informational | http://web:8080 | Percentage of responses with status code 2xx | 95 % |
| Info | Informational | http://web:8080 | Percentage of responses with status code 4xx | 4 % |
| Info | Informational | http://web:8080 | Percentage of endpoints with content type application/javascript | 42 % |
| Info | Informational | http://web:8080 | Percentage of endpoints with content type font/woff2 | 9 % |
| Info | Informational | http://web:8080 | Percentage of endpoints with content type image/png | 9 % |
| Info | Informational | http://web:8080 | Percentage of endpoints with content type text/css | 4 % |
| Info | Informational | http://web:8080 | Percentage of endpoints with content type text/html | 19 % |
| Info | Informational | http://web:8080 | Percentage of endpoints with content type text/plain | 9 % |
| Info | Informational | http://web:8080 | Percentage of endpoints with content type text/xml | 4 % |
| Info | Informational | http://web:8080 | Percentage of endpoints with method GET | 100 % |
| Info | Informational | http://web:8080 | Count of total endpoints | 21    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| Application Error Disclosure | Medium | 1 |
| CSP: style-src unsafe-inline | Medium | 5 |
| Modern Web Application | Informational | 1 |




## Alert Detail



### [ Application Error Disclosure ](https://www.zaproxy.org/docs/alerts/90022/)



##### Medium (Medium)

### Description

This page contains an error/warning message that may disclose sensitive information like the location of the file that produced the unhandled exception. This information can be used to launch further attacks against the web application. The alert could be a false positive if the error message is found inside a documentation page.

* URL: http://web:8080/privacy-policy
  * Node Name: `http://web:8080/privacy-policy`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `Error Report`
  * Other Info: ``


Instances: 1

### Solution

Review the source code of this page. Implement custom error pages. Consider implementing a mechanism to provide a unique error reference/identifier to the client (browser) while logging the details on the server side and not exposing them to the user.

### Reference



#### CWE Id: [ 550 ](https://cwe.mitre.org/data/definitions/550.html)


#### WASC Id: 13

#### Source ID: 3

### [ CSP: style-src unsafe-inline ](https://www.zaproxy.org/docs/alerts/10055/)



##### Medium (High)

### Description

Content Security Policy (CSP) is an added layer of security that helps to detect and mitigate certain types of attacks. Including (but not limited to) Cross Site Scripting (XSS), and data injection attacks. These attacks are used for everything from data theft to site defacement or distribution of malware. CSP provides a set of standard HTTP headers that allow website owners to declare approved sources of content that browsers should be allowed to load on that page — covered types are JavaScript, CSS, HTML frames, fonts, images and embeddable objects such as Java applets, ActiveX, audio and video files.

* URL: http://web:8080
  * Node Name: `http://web:8080`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'; script-src 'self' 'sha256-DD8Y4R0zwNp7USc9iqgGQziuRtXwONqR6lifdj8ob/g=' 'sha256-OBTN3RiyCV4Bq7dFqZ5a2pAXjnCcCYeTJMO2I/LYKeo=' 'sha256-W8FeE0GfuGdYlm39nwkI9eRWSMVpuNhHLFEPX2NCaUc=' 'sha256-j1yMGMVItJXsojfCn3/RmVsP0F2jUnPAtCpfEE5kBDU=' 'sha256-lxzIcgOJMBlyNeCPWIDqH2rbS7KhCHkj1Nm2bxymqhg='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://localhost:8000; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests`
  * Other Info: `style-src includes unsafe-inline.`
* URL: http://web:8080/
  * Node Name: `http://web:8080/`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'; script-src 'self' 'sha256-DD8Y4R0zwNp7USc9iqgGQziuRtXwONqR6lifdj8ob/g=' 'sha256-OBTN3RiyCV4Bq7dFqZ5a2pAXjnCcCYeTJMO2I/LYKeo=' 'sha256-W8FeE0GfuGdYlm39nwkI9eRWSMVpuNhHLFEPX2NCaUc=' 'sha256-j1yMGMVItJXsojfCn3/RmVsP0F2jUnPAtCpfEE5kBDU=' 'sha256-lxzIcgOJMBlyNeCPWIDqH2rbS7KhCHkj1Nm2bxymqhg='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://localhost:8000; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests`
  * Other Info: `style-src includes unsafe-inline.`
* URL: http://web:8080/%3Fdomain=ZAP
  * Node Name: `http://web:8080/ (domain)`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'; script-src 'self' 'sha256-DD8Y4R0zwNp7USc9iqgGQziuRtXwONqR6lifdj8ob/g=' 'sha256-OBTN3RiyCV4Bq7dFqZ5a2pAXjnCcCYeTJMO2I/LYKeo=' 'sha256-W8FeE0GfuGdYlm39nwkI9eRWSMVpuNhHLFEPX2NCaUc=' 'sha256-j1yMGMVItJXsojfCn3/RmVsP0F2jUnPAtCpfEE5kBDU=' 'sha256-lxzIcgOJMBlyNeCPWIDqH2rbS7KhCHkj1Nm2bxymqhg='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://localhost:8000; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests`
  * Other Info: `style-src includes unsafe-inline.`
* URL: http://web:8080/64
  * Node Name: `http://web:8080/64`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'; script-src 'self' 'sha256-DD8Y4R0zwNp7USc9iqgGQziuRtXwONqR6lifdj8ob/g=' 'sha256-OBTN3RiyCV4Bq7dFqZ5a2pAXjnCcCYeTJMO2I/LYKeo=' 'sha256-W8FeE0GfuGdYlm39nwkI9eRWSMVpuNhHLFEPX2NCaUc=' 'sha256-j1yMGMVItJXsojfCn3/RmVsP0F2jUnPAtCpfEE5kBDU=' 'sha256-lxzIcgOJMBlyNeCPWIDqH2rbS7KhCHkj1Nm2bxymqhg='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://localhost:8000; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests`
  * Other Info: `style-src includes unsafe-inline.`
* URL: http://web:8080/privacy-policy
  * Node Name: `http://web:8080/privacy-policy`
  * Method: `GET`
  * Parameter: `Content-Security-Policy`
  * Attack: ``
  * Evidence: `default-src 'self'; script-src 'self' 'sha256-DD8Y4R0zwNp7USc9iqgGQziuRtXwONqR6lifdj8ob/g=' 'sha256-OBTN3RiyCV4Bq7dFqZ5a2pAXjnCcCYeTJMO2I/LYKeo=' 'sha256-W8FeE0GfuGdYlm39nwkI9eRWSMVpuNhHLFEPX2NCaUc=' 'sha256-j1yMGMVItJXsojfCn3/RmVsP0F2jUnPAtCpfEE5kBDU=' 'sha256-lxzIcgOJMBlyNeCPWIDqH2rbS7KhCHkj1Nm2bxymqhg='; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self' http://localhost:8000; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'; upgrade-insecure-requests`
  * Other Info: `style-src includes unsafe-inline.`


Instances: 5

### Solution

Ensure that your web server, application server, load balancer, etc. is properly configured to set the Content-Security-Policy header.

### Reference


* [ https://www.w3.org/TR/CSP/ ](https://www.w3.org/TR/CSP/)
* [ https://caniuse.com/#search=content+security+policy ](https://caniuse.com/#search=content+security+policy)
* [ https://content-security-policy.com/ ](https://content-security-policy.com/)
* [ https://github.com/HtmlUnit/htmlunit-csp ](https://github.com/HtmlUnit/htmlunit-csp)
* [ https://web.dev/articles/csp#resource-options ](https://web.dev/articles/csp#resource-options)


#### CWE Id: [ 693 ](https://cwe.mitre.org/data/definitions/693.html)


#### WASC Id: 15

#### Source ID: 3

### [ Modern Web Application ](https://www.zaproxy.org/docs/alerts/10109/)



##### Informational (Medium)

### Description

The application appears to be a modern web application. If you need to explore it automatically then the Client Spider may well be more effective than the standard one.

* URL: http://web:8080/64
  * Node Name: `http://web:8080/64`
  * Method: `GET`
  * Parameter: ``
  * Attack: ``
  * Evidence: `<script src="/_next/static/chunks/1zw0bsrn8gi_j.js" async=""></script>`
  * Other Info: `No links have been found while there are scripts, which is an indication that this is a modern web application.`


Instances: 1

### Solution

This is an informational alert and so no changes are required.

### Reference




#### Source ID: 3


