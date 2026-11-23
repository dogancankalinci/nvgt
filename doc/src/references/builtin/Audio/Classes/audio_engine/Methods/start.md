# start
Begin producing audio.

`bool audio_engine::start();`

## Returns:
bool: true if the engine started.

## Remarks:
Engines start automatically unless AUDIO_ENGINE_NO_AUTO_START was passed to their constructor, or `stop()` was called. An engine made with AUDIO_ENGINE_NO_DEVICE has no device to start, so this returns false for it with `SOUNDSYSTEM_LAST_ERROR` set to `AUDIO_ERROR_STATE_INVALID_OPERATION`; such an engine produces audio whenever `read()` is called.
