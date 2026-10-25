# play
Starts playing the sound.

`bool sound::play();`

## Returns:
bool: true if the sound was able to start playing, false otherwise.

## Remarks:
A sound fed by stream_pcm(), which starts playing on its first call, drops what was queued when play() starts it again after it was stopped, so that it plays only what is queued from then on; one already playing, due to start at a time set with set_start_time(), or paused with pause() or pause_fade(), keeps it.
