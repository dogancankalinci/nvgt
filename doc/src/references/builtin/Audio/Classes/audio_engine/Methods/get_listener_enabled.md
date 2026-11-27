# get_listener_enabled
Check whether a listener is enabled.

`bool audio_engine::get_listener_enabled(int index) const;`

## Arguments:
* int index: the number of the listener, starting at 0. Engines have one listener by default.

## Returns:
bool: true if the listener is enabled; false for a listener the engine doesn't have, which sets SOUNDSYSTEM_LAST_ERROR to AUDIO_ERROR_STATE_INVALID_ARGS.
