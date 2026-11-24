# pause_fade_in_milliseconds
Fade the sound out over a number of milliseconds and then pause it.

`bool sound::pause_fade_in_milliseconds(const uint64 length_in_milliseconds);`

## Arguments:
* const uint64 length_in_milliseconds: how long the fade takes in milliseconds.

## Returns:
bool: true if the fade was started, or if the sound isn't playing, which leaves it as it is, as `pause()` does; false if nothing is loaded, or if the length is too long to count in frames.

## Remarks:
This is the same as `pause_fade()` but always measures the length in milliseconds.
