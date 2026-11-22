# hf_reference
The frequency in hertz above which `hf_rolloff` applies.

`float audio_fdn_reverb_node::hf_reference;`

## Remarks:
The default is 500. The high frequencies start no lower than where the low ones end, so a value below `lf_reference` is treated as the same one, and frequencies above 0.45 of the engine's sample rate are treated as that.
