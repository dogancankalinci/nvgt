# file_copy
Copies a file or a directory from one location to another.

`bool file_copy(const string&in source_filename, const string&in destination_filename, bool overwrite = false);`

## Arguments:
* const string&in source_filename: the path/name of the file or directory to be copied.
* const string&in destination_filename: the path (including filename) to copy the file or directory to. If a directory already exists there, or the path ends with a slash, the source is copied into that directory under its own name.
* bool overwrite = false: whether a file that already exists at the destination is replaced. Without it, such a file makes the copy fail.

## Returns:
bool: true if the file or directory was successfully copied, false otherwise.

## Remarks:
A directory is copied with everything in it. A link inside it is copied as what it points to, so a link to a directory brings a copy of that directory's contents. A directory that would be copied into itself fails the copy: a link to the directory being copied or to one above it, or a destination inside the source. A copy that fails part way leaves what it had copied so far.
