# play_wait
Starts playing the sound, blocking the calling thread until it's finished.

`bool sound::play_wait();`

## Returns:
bool: true once the sound has stopped playing, false if it couldn't be played, or is fed by stream_pcm(), which gives it no end to wait for (SOUNDSYSTEM_LAST_ERROR is then AUDIO_ERROR_STATE_INVALID_OPERATION).

## Remarks:
It returns as soon as the sound stops playing for any reason: at its end, or when another thread stops or pauses it, which also returns true.

Called on an audio thread, as from an audio engine's processing callback, it returns false and SOUNDSYSTEM_LAST_ERROR is AUDIO_ERROR_STATE_INVALID_OPERATION: waiting there would hold that engine's audio up for the sound's length, and for good for a sound of that engine, which can't play on meanwhile.
