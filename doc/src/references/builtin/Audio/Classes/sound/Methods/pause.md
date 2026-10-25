# pause
Pauses the sound.

`bool sound::pause();`

## Returns:
bool: true if the sound was paused, or wasn't playing (see remarks), false otherwise.

## Remarks:
play() resumes a paused sound. A sound fed by stream_pcm() keeps what was queued while it is paused, and plays it on from there once resumed.

A sound that isn't playing, as one stopped, played to its end or never started, is left as it was: pause() returns true, but the sound doesn't read as paused, and play() starts it as it would have without the pause. One whose start was scheduled ahead with set_start_time() counts as playing: it is paused, and play() resumes it, to start at that time.
