# load
Loads a sound file.

`bool sound::load(const string&in filename, const pack_interface@+ pack = sound_default_pack);`

## Arguments:
* const string&in filename: the name or path of the file to load.
* const pack_interface@+ pack = sound_default_pack: the pack to load the file from; null loads it from disk.

## Returns:
bool: true if the sound was successfully loaded, false otherwise.

## Remarks:
A sound already loaded into this object is closed first. When loading fails, SOUNDSYSTEM_LAST_ERROR tells why.
