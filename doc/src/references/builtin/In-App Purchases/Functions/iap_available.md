# iap_available
Determine whether in-app purchases are available on the current device.

`bool iap_available();`

## Returns:
bool: true if the store/billing service is available and IAP can be used, false otherwise.

## Remarks:
Always call this before attempting any other IAP operation. Billing can be unavailable for many reasons: the platform does not support it, the device has no store account configured, or the app was not built with in-app purchase support. If this returns false, hide or disable your store interface rather than calling the other functions.
