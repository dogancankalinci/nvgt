# iap_get_last_error
Retrieve a human-readable description of the most recent in-app purchase error.

`string iap_get_last_error();`

## Returns:
string: the last error message recorded by the billing system, or an empty string if no error has occurred.

## Remarks:
Call this after any IAP operation reports failure (for example when a function returns false, or when a purchase comes back with the IAP_PURCHASE_FAILED state) to find out what went wrong. The message comes from the underlying store and is intended for logging or diagnostics; it is not necessarily localized for end users.
