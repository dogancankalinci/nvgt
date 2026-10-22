# set_position_3d
Places the sound in 3d space.

1. `void sound::set_position_3d(float x, float y, float z);`
2. `void sound::set_position_3d(const vector&in position);`

## Arguments (1):
* float x: the x coordinate of the sound.
* float y: the y coordinate of the sound.
* float z: the z coordinate of the sound.

## Arguments (2):
* const vector&in position: the position of the sound.

## Remarks:
The position is in the same space as the listener's, set with sound_set_listener_position(). Setting it turns spatialization on for the sound, and the first time also applies sound_default_3d_panner and sound_default_3d_attenuator unless the sound has panners of its own. A sound without anything loaded is left alone.

The sound's effects_chain always runs before its positioning, whichever was made first, so effects such as a reverb or a delay are placed with the sound rather than applied to it after it was panned and attenuated.
