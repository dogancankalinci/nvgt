# seek
Seeks to a particular point in the sound.

`bool sound::seek(uint64 position);`

## Arguments:
* uint64 position: the point to seek to, in milliseconds, or in frames when the sound's engine was made with AUDIO_ENGINE_DURATIONS_IN_FRAMES.

## Returns:
bool: true if the seeking was successful, false otherwise, as for a stream without a length.

## Remarks:
A sound playing a chain of data sources, opened with open(), seeks in the whole chain, from the source its head was on when it was opened: the position counts from that source's start through each source after it. Such a sound can be sought back to its start even when the chain's length is unknown.
