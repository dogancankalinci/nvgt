# load
Loads a sound file.

`bool sound::load(const string&in filename, const pack_interface@+ pack = sound_default_pack);`

## Arguments:
* const string&in filename: the name or path of the file to load.
* const pack_interface@+ pack = sound_default_pack: the pack to load the file from; null, or a pack that isn't open, loads it from disk.

## Returns:
bool: true if the sound was successfully loaded, false otherwise.

## Remarks:
A sound already loaded into this object is closed first. When loading fails, SOUNDSYSTEM_LAST_ERROR tells why. A pack open for writing rather than reading can't be loaded from: passing one throws an exception instead, as does load() with sound_default_pack opened for writing since it was assigned. The same goes for stream(), sound_play() and the other functions that load audio from a pack.

The file is decoded in the background after load returns, and the load_complete property tells when that is done. A sound played or sought before then plays what is decoded, and at a point not yet decoded waits for it rather than skipping it, so an engine without a device read faster than the decoding gets silence there, followed by the sound from that point.

Sounds loaded from the same file share its decoded data while any of them is loaded: a relative name is taken from the current directory, and a pack by its file and its place in that file, so files of the same name in different directories or packs are never confused. A file changed on disk while a sound loaded from it is still loaded is read as it was by further loads, until every sound loaded from it has been closed.
