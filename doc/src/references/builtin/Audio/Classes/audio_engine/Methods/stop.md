# stop
Pause the engine.

`bool audio_engine::stop();`

## Returns:
bool: true if the engine stopped.

## Remarks:
Nothing is played and no time passes for sounds while the engine is stopped. Call `start()` to resume. An engine made with AUDIO_ENGINE_NO_DEVICE has no device to stop, so this returns false for it with `SOUNDSYSTEM_LAST_ERROR` set to `AUDIO_ERROR_STATE_INVALID_OPERATION`.
