# Introduction
This is a WEB API for verifying JWT token.

## Example
+ Please use http://52.151.25.73:8080/api/jwt/checkAADJWT?tenantId=06aa9b7a-f7ae-4e01-9581-a769e9fc1bd6&clientId=a20ecdc7-18c5-4e42-81e7-c6153fa00e5c&token=

+ Sample expired token:
  * ```
    eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6ImppYk5ia0ZTU2JteFBZck45Q0ZxUms0SzRndyIsImtpZCI6ImppYk5ia0ZTU2JteFBZck45Q0ZxUms0SzRndyJ9.eyJhdWQiOiJhcGk6Ly9mYWEwYWZiOC1iZmU1LTQ2NDgtODJlOS1jNmYzYjkwOWZjZjQiLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC8wNmFhOWI3YS1mN2FlLTRlMDEtOTU4MS1hNzY5ZTlmYzFiZDYvIiwiaWF0IjoxNTk3ODA4Mjg3LCJuYmYiOjE1OTc4MDgyODcsImV4cCI6MTU5NzgxMjE4NywiYWNyIjoiMSIsImFpbyI6IkFTUUEyLzhRQUFBQXNiRkJvR2swcFJHYzJWSTgxS0ovay8xZFEvc1RNMkhTaUwwbXVmMWo0Tms9IiwiYW1yIjpbInB3ZCJdLCJhcHBpZCI6ImEyMGVjZGM3LTE4YzUtNGU0Mi04MWU3LWM2MTUzZmEwMGU1YyIsImFwcGlkYWNyIjoiMSIsImZhbWlseV9uYW1lIjoi5rWm5bGxIiwiZ2l2ZW5fbmFtZSI6IuWkp-i8nSIsImlwYWRkciI6IjIxMC43NC4xNTYuMjUwIiwibmFtZSI6Im0tdXJheWFtYSIsIm9pZCI6ImQ5NmI3YTBjLTE5YzYtNDMwYi1iZjhmLTgyNTQ2NzhiZWMyMyIsInNjcCI6IlRva2VuLlZhbGlkYXRpb24iLCJzdWIiOiJoeERtM3lSUXZnTXFhVDk5eEt6eV9fYUxMT1ltTHJaaU1NSE5od2MxdDJVIiwidGlkIjoiMDZhYTliN2EtZjdhZS00ZTAxLTk1ODEtYTc2OWU5ZmMxYmQ2IiwidW5pcXVlX25hbWUiOiJtLXVyYXlhbWFAQUFEUmVzZWFyY2hGb3JVc2Vycy5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJtLXVyYXlhbWFAQUFEUmVzZWFyY2hGb3JVc2Vycy5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJwMVEzTmdtOGhFR1ZxUURGaU9nbkFBIiwidmVyIjoiMS4wIn0.VKVupXLUr6dR1BPWTevl9Xj2J6FWzVDq3S-i2hKelmkna-HsJLmwp28SKsl76FJsEzumPN3Ld-gAksvS1bW4AhAx4qvf_O0FQ-OaEtIrjvqt0ObvKU4jpOnou82oi4GGqaZv0E5mxI4LLNs7KPrFDTTgSxQslbwbRxueZhYNKZD1gjOnC2_OsnOTlqgr_2Js-iT0k3DlK8C-X1IsxdnuSCNZm0drm1tx9C-JRfLB-_plG7MNw6glQXKGiogm13GCpvikrvwI5uI2wbCZLKq28n5bURXrki45jmD1XChs02GxJ-CgbKVU_E3kT7D9ef7DxuPmNIm8zQSO9ChPkM9X9Q
    ```

## URI Parameters
  |Name|In|Required|Type|Description|
  |-----|-----|-----|-----|-----|
  |tenantId|path|True|string|The name of Azure AD tenant|
  |clientId|path|True|string|The name of Azure AD Application ID|
  |token|path|True|string|The name of access token|

## Responses
+ If the token validation is successful, server will return the response body as follow.
```
{"status":true,"message":"Token is vaild"}
```