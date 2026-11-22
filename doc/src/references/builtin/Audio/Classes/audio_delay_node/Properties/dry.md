# dry
The volume at which audio enters the effect, as a linear gain where 1 is full volume.

`float audio_delay_node::dry;`

## Remarks:
The default is 1. This applies to the audio as it goes in, so it scales both the direct sound and the echoes made from it. Setting it to 0 lets nothing new in, while the echoes already being made carry on until they have faded.
