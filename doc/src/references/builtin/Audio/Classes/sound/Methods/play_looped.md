# play_looped
Starts playing the sound repeatedly.

`bool sound::play_looped();`

## Returns:
bool: true if the sound was able to start playing, false otherwise.

## Remarks:
A sound whose source can't seek back to where its loop starts, as a stream from stream_url() or a decoder of a datastream that can't seek, or a chain holding such a source, ends after one pass instead, as play() ends it. Started again once it ended, by play() or play_looped(), such a sound can't go back to its start, so either returns false, and SOUNDSYSTEM_LAST_ERROR tells why.
