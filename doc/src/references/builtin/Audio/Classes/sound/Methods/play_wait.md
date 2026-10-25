# play_wait
Starts playing the sound, blocking the calling thread until it's finished.

`bool sound::play_wait();`

## Returns:
bool: true if the sound has successfully loaded and finished playing, false otherwise.

## Remarks:
Called on an audio thread, as from an audio engine's processing callback, it returns false and SOUNDSYSTEM_LAST_ERROR is AUDIO_ERROR_STATE_INVALID_OPERATION: waiting there holds up the very audio the sound needs to play.
