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

The file is decoded in the background after load returns, and the load_complete property tells when that is done. A sound played or sought before then plays what is decoded, and at a point not yet decoded waits for it rather than skipping it, so an engine without a device read faster than the decoding gets silence there, followed by the sound from that point.
