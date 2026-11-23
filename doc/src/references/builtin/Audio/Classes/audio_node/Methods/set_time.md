# set_time
Set the node's local clock.

`bool audio_node::set_time(uint64 local_time);`

## Arguments:
* uint64 local_time: the new time, in PCM frames, or for a sound, mixer or engine in the engine's unit of time, milliseconds unless the engine was made with AUDIO_ENGINE_DURATIONS_IN_FRAMES; see the `time` property.

## Returns:
bool: true if the time was set.

## Remarks:
See the `time` property.
