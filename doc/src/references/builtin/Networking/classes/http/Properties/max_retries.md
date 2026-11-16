# max_retries
The most attempts a request makes, the first one included.

`uint max_retries;`

## Remarks:
Each redirect the request follows (status 301, 302, 303 or 307) and each time it is sent again with credentials after a 401 response is one more attempt. Once they are used up, the last response received is the result, a redirect's status and headers for example. The default is 10, so a request follows up to 9 redirects; 0 is taken as 1, one attempt that follows no redirect.

A request that fails, such as a connection that is refused or times out or a host name that can't be found, is not tried again whatever this property is set to: it ends at once with no response, and status_code is 0.

Set it before calling get, post or another request method; it applies to every request of this object until reset(true) sets it back to 10.
