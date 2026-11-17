# generate_system_fingerprint
Generate a string that identifies the device the application is running on.

1. `string generate_system_fingerprint(const string&in application_id = "");`
2. `string generate_system_fingerprint_legacy1(const string&in application_id = "");`

## Arguments:
* const string&in application_id = "": a string of your own that is mixed into the fingerprint, so that two applications get different fingerprints on the same device.

## Returns:
string: the fingerprint, always 64 bytes long.

## Remarks:
The fingerprint is derived from properties of the device: on Windows, Linux and macOS from the amount of memory, processor information and the system volume, on Android from the device's ID, and on iOS from the identifier for the vendor. The same device and application_id give the same fingerprint every time, so it can be stored and compared later, for instance to tie a license or a saved account to a device. It changes when the properties it is made from change, such as a memory upgrade or a new system volume, and on iOS when every application of the vendor was removed.

The fingerprint is not plain text. Each byte of a SHA-256 hash becomes two bytes, taken from a reduced set of characters: the first of the two is one of `02468ACE`, and the second is one of `02468ACEGIKMOQSUWYacegikmoqsuwy` or a 0 (NUL) byte. About half of all fingerprints contain at least one NUL byte. So treat the result as binary data: compare and store the whole string (for instance with a file opened in binary mode, or after string_base64_encode()), and do not pass it to anything that stops at a NUL byte, such as a C library function or a text field, which would see only part of it. The format is kept as it is because applications have already stored fingerprints made with it.

generate_system_fingerprint_legacy1() is the fingerprint of earlier NVGT versions, which used the network adapters' hardware (MAC) addresses on Windows, Linux and macOS instead of the memory and processor information, and changed whenever the network adapters did. It is only there so that fingerprints stored by older versions of an application can still be recognized; new code should use generate_system_fingerprint().
