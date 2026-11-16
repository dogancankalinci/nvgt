# adler32
Calculate the Adler-32 checksum of a string.

`uint adler32(const string&in data);`

## Arguments:
* const string&in data: the bytes to checksum.

## Returns:
uint: the Adler-32 checksum of the data, or 0 if the string is empty.

## Remarks:
Adler-32 is the checksum zlib uses: it is quick to compute and catches accidental changes to data, but it is not a cryptographic hash, so use one of the string_hash functions when the data could have been changed on purpose.

An empty string gives 0. The algorithm itself gives 1 for no data (the value zlib's adler32() returns for an empty buffer), so if you compare with checksums made by other software, treat an empty string as a special case. NVGT has always returned 0 here, and keeps doing so, so that checksums stored by existing scripts stay valid.
