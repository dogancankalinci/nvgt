# lf_reference
The frequency in hertz below which `lf_rolloff` applies.

`float audio_fdn_reverb_node::lf_reference;`

## Remarks:
The default is 200. Frequencies below 20 hertz are treated as 20, and ones above 0.45 of the engine's sample rate as that.
