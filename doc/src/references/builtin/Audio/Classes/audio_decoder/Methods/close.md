# close
Close the file or stream the decoder has open.

`bool audio_decoder::close();`

## Returns:
bool: true if something was closed; false if nothing was open, or if the decoder is in use, played by a sound or linked from another source with `set_next()`, in which case it stays open. SOUNDSYSTEM_LAST_ERROR is AUDIO_ERROR_STATE_INVALID_OPERATION either way.
