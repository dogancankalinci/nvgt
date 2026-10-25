# play_looped
Starts playing the sound repeatedly.

`bool sound::play_looped();`

## Returns:
bool: true if the sound was able to start playing, false otherwise.

## Remarks:
A sound whose source can't seek back to where its loop starts ends after one pass instead, as play() ends it: a stream from stream_url() or a decoder of a datastream that can't seek, once read past what it keeps to go back to (an Ogg Vorbis or Opus decoder of such a datastream never can go back), or a chain holding such a source. Started again once it ended, by play() or play_looped(), a decoder or chain like this can't go back to its start, so either returns false, and SOUNDSYSTEM_LAST_ERROR tells why; a stream from stream_url() returns true, but plays nothing and ends at once. So does either call made just as such a sound reaches its end on an engine without a device, from the audio thread, as in a processing callback, or while nothing processes the sound, as with its engine or its mixer stopped, where it can't wait for the sound's end to be done with.
