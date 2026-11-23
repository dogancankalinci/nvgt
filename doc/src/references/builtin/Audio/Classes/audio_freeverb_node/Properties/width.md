# width
The stereo width of the reverb, usually between 0 and 1.

`float audio_freeverb_node::width;`

## Remarks:
The default is 1, a fully stereo reverb. At 0 the reverb is the same in both channels. Values above 1 widen it further and negative ones swap its channels, while a width that would make the reverb louder than the gain limit of 100000 is refused.
