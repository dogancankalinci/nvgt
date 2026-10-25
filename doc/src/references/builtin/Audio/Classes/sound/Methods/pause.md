# pause
Pauses the sound.

`bool sound::pause();`

## Returns:
bool: true if the sound was paused, false otherwise.

## Remarks:
play() resumes a paused sound. A sound fed by stream_pcm() keeps what was queued while it is paused, and plays it on from there once resumed.
