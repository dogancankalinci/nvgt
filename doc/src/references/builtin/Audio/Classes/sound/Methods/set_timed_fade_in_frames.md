# set_timed_fade_in_frames
Schedule a fade of the sound's volume, with its length and start time in PCM frames.

`void sound::set_timed_fade_in_frames(float start_volume, float end_volume, uint64 length, uint64 absolute_time);`

## Arguments:
* float start_volume: the volume to start from, or FLOAT_MAX for the current volume of the fade, see `set_timed_fade()`.
* float end_volume: the volume to end at.
* uint64 length: how long the fade takes in frames.
* uint64 absolute_time: when it starts on the engine's clock, in frames.

## Remarks:
This is the same as `set_timed_fade()` but always measures in frames.
