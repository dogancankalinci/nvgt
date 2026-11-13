# directory_delete
Deletes a directory.

`bool directory_delete(const string&in directory, bool recursive = true);`

## Arguments:
* const string&in directory: the directory to delete.
* bool recursive = true: whether to delete everything inside the directory as well; when false, only an empty directory can be deleted.

## Returns:
bool: true if the directory was successfully deleted, false otherwise.

## Remarks:
A symbolic link or (on Windows) a junction found inside the directory is deleted itself; the place it points to and what is there are left alone. The same goes for a directory argument that is such a link.
