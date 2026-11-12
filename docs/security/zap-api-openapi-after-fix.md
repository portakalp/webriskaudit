# ZAP Scanning Report

ZAP by [Checkmarx](https://checkmarx.com/).


## Summary of Alerts

| Risk Level | Number of Alerts |
| --- | --- |
| High | 0 |
| Medium | 0 |
| Low | 0 |
| Informational | 1 |




## Insights

| Level | Reason | Site | Description | Statistic |
| --- | --- | --- | --- | --- |
| Low | Warning |  | ZAP errors logged - see the zap.log file for details | 10    |
| Info | Informational |  | Percentage of network failures | 69 % |
| Info | Informational | http://api:8000 | Percentage of responses with status code 2xx | 75 % |
| Info | Informational | http://api:8000 | Percentage of responses with status code 4xx | 25 % |
| Info | Informational | http://api:8000 | Percentage of endpoints with content type application/json | 75 % |
| Info | Informational | http://api:8000 | Percentage of endpoints with content type application/problem+json | 25 % |
| Info | Informational | http://api:8000 | Percentage of endpoints with method GET | 75 % |
| Info | Informational | http://api:8000 | Percentage of endpoints with method POST | 25 % |
| Info | Informational | http://api:8000 | Count of total endpoints | 4    |







## Alerts

| Name | Risk Level | Number of Instances |
| --- | --- | --- |
| A Client Error response code was returned by the server | Informational | 1 |




## Alert Detail



### [ A Client Error response code was returned by the server ](https://www.zaproxy.org/docs/alerts/100000/)



##### Informational (High)

### Description

A response code of 422 was returned by the server.
This may indicate that the application is failing to handle unexpected input correctly.
Raised by the 'Alert on HTTP Response Code Error' script

* URL: http://api:8000/api/v1/scan
  * Node Name: `http://api:8000/api/v1/scan ()({domain})`
  * Method: `POST`
  * Parameter: ``
  * Attack: ``
  * Evidence: `422`
  * Other Info: ``


Instances: 1

### Solution



### Reference



#### CWE Id: [ 388 ](https://cwe.mitre.org/data/definitions/388.html)


#### WASC Id: 20

#### Source ID: 4


