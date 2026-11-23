# pinned_listener
The index of a listener that the mixer is always heard from, or 255 for none, so that it is heard from the closest listener.

`uint mixer::pinned_listener;`

## Remarks:
This only matters in an engine with more than one listener, such as a split screen game. A mixer is pinned to listener 0 by default; set this to 255 to have it heard from whichever enabled listener is closest. Setting it to a listener the engine doesn't have is refused with `SOUNDSYSTEM_LAST_ERROR` set to `AUDIO_ERROR_STATE_INVALID_ARGS`.
