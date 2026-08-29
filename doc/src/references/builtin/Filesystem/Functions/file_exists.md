# file_exists
Check for the existence of a particular file.

`bool file_exists(const string&in file_path);`

## Arguments:
* const string&in file_path: the path to the file to query.

## Returns:
bool: true if the file exists, false otherwise.

## Remarks:
On Android, a relative path that is not present on the filesystem is also looked up in the app's assets, which is where files included with `#pragma asset` end up. This means that the function agrees with `sound.load`, `pack` and the datastreams, all of which can open assets directly. Absolute paths are only ever checked against the filesystem, as an absolute path can never refer to an asset.
