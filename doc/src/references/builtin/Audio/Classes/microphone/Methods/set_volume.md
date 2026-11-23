# set_volume
Set the recording volume.

`void microphone::set_volume(float volume);`

## Arguments:
* float volume: the volume in decibels, 0 or lower, where 0 is unchanged. A positive volume is refused, with `SOUNDSYSTEM_LAST_ERROR` set to `AUDIO_ERROR_STATE_INVALID_ARGS`, as a device records no louder than it is.
