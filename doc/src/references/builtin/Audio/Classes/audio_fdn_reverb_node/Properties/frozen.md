# frozen
Whether the reverb holds its current tail forever and ignores new input.

`bool audio_fdn_reverb_node::frozen;`

## Remarks:
Setting it back to false lets the tail decay as normal. With a `modulation_depth` above 0 a frozen tail still fades very slowly, as modulating it loses a little of it; set that to 0 to hold it for good.
