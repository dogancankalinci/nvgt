# volume
The recording volume in decibels, where 0 is unchanged and lower values are quieter.

`float microphone::volume;`

## Remarks:
It can be set at any time, also while recording, and is kept when `set_device()` opens another device. A device records no louder than it is, so a positive volume is refused, with `SOUNDSYSTEM_LAST_ERROR` set to `AUDIO_ERROR_STATE_INVALID_ARGS`.
