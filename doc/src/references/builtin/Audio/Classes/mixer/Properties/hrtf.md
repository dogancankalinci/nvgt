# hrtf
Whether the mixer is spatialized with HRTF.

`bool mixer::hrtf;`

## Remarks:
Setting this to true selects the HRTF panner and attenuator, which make a positioned mixer sound as though it is in a direction around the listener, in front, behind, above or below, and work best with headphones. Setting it to false selects the basic panner and attenuator, which only change the volume of each speaker. It is true when both the panner and the attenuator in use are the HRTF ones, so it stays false for a mixer that HRTF can't be used for, such as one in an engine that isn't stereo. See also `set_3d_panner()` to choose another panner, such as one from a plugin, and `sound_global_hrtf` to set the default for all sounds.
