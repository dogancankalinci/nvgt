# retry_delay
The milliseconds a request waits before each attempt after the first.

`uint retry_delay;`

## Remarks:
The wait comes before following a redirect and before sending the request again with credentials after a 401 response (see max_retries). The first attempt starts at once. A request that fails is not tried again, so there is no wait after a failure.

The default is 0. Set it before calling get, post or another request method; it applies to every request of this object until reset(true) sets it back to 0. Calling reset(), or the object going, cancels a wait in progress.
