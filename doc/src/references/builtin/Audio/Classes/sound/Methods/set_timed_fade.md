# set_timed_fade
Schedule a fade of the sound's volume to start at a time on the engine's clock.

`void sound::set_timed_fade(float start_volume, float end_volume, uint64 length, uint64 absolute_time);`

## Arguments:
* float start_volume: the volume to start the fade from. Pass FLOAT_MAX to start from the current volume of the fade.
* float end_volume: the volume to end at.
* uint64 length: how long the fade takes, in milliseconds unless the engine was created with AUDIO_ENGINE_DURATIONS_IN_FRAMES, in which case it is in PCM frames.
* uint64 absolute_time: when the fade starts on the engine's clock, see `audio_engine::time_in_milliseconds`, in milliseconds unless the engine was created with AUDIO_ENGINE_DURATIONS_IN_FRAMES, in which case it is in PCM frames.

## Remarks:
The volumes are in the same units as those of `set_fade()`, so they are in decibels in the default engine. Scheduling a fade lets it be lined up precisely with music or with other scheduled sounds.
