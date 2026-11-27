# get_listener_position
Get the position of a listener.

`vector@ audio_engine::get_listener_position(int index) const;`

## Arguments:
* int index: the number of the listener, starting at 0. Engines have one listener by default.

## Returns:
vector@: the position. For a listener the engine doesn't have, as every engine has only listener 0, it gives NaN coordinates and sets SOUNDSYSTEM_LAST_ERROR to AUDIO_ERROR_STATE_INVALID_ARGS.
