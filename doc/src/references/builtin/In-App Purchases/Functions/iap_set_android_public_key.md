# iap_set_android_public_key
Provide the Google Play billing public license key used to verify purchases on Android.

`void iap_set_android_public_key(const string&in key);`

## Arguments:
* const string&in key: your app's base64-encoded RSA public license key, found in the Google Play Console under your app's monetization/licensing settings.

## Remarks:
This is only relevant on Android and should be called once, before querying products or making purchases. It has no effect on other platforms, so it is safe (and recommended) to call it unconditionally in your setup code. The key allows the billing library to validate that purchase responses genuinely came from Google Play.
