# seek
Seeks to a particular point in the sound.

`bool sound::seek(uint64 position);`

## Arguments:
* uint64 position: the point to seek to, in milliseconds, or in frames when the sound's engine was made with AUDIO_ENGINE_DURATIONS_IN_FRAMES.

## Returns:
bool: true if the seeking was successful, false otherwise, as for a stream without a length.

## Remarks:
A sound at its end makes the seek when it is played again; one whose source can't go back to its start can't be played again (see play_looped()), and the seek is dropped when play() or play_looped() fails, its position reading the end again.

A sound playing a chain of data sources, opened with open(), seeks in the whole chain, from the source its head was on when it was opened, or the head itself from its start if it was on none: the position counts from that source's start through each source after it. Such a sound can be sought back to its start even when the chain's length is unknown. A seek back past a source that can't seek back to its start, as a decoder of a datastream that can't seek, passes over that source once it played through, and once the chain ended, such a sound can't be started again (see play_looped()).
