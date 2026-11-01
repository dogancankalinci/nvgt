# loaded_filename
Obtain the name the sound was loaded from.

`string sound::loaded_filename;`

## Remarks:
This is the file name or URL given to load(), stream() or stream_url(), as it was given. A sound that wasn't loaded from a file has one of these names instead:
* "::memory" for load_memory() and load_string().
* ":quickstring" for load_string_async().
* ":pcm" for load_pcm() and stream_pcm().
* ":datasource" for open().

It's an empty string while nothing is loaded.
