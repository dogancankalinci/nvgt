# volume
The recording volume in decibels, where 0 is unchanged.

`float microphone::volume;`

## Remarks:
It can be set at any time, also while recording, and is kept when `set_device()` opens another device.
