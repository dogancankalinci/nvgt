# seek
Seeks to a particular point in the sound.

`bool sound::seek(uint64 position);`

## Arguments:
* uint64 position: the point to seek to, in milliseconds, or in frames when the sound's engine was made with AUDIO_ENGINE_DURATIONS_IN_FRAMES.

## Returns:
bool: true if the seeking was successful, false otherwise, as for a stream without a length.
