# sound_get_listener_position
Get the position of a listener of the default engine.

`vector@ sound_get_listener_position(uint listener_index = 0);`

## Arguments:
* uint listener_index = 0: the listener to get the position of.

## Returns:
vector@: the position of the listener, or NaN coordinates for one the default engine doesn't have, with SOUNDSYSTEM_LAST_ERROR set to AUDIO_ERROR_STATE_INVALID_ARGS.

## Remarks:
This is the same as `sound_default_engine.get_listener_position()`.
