# decay
How much of each echo is fed back into the delay to make the next one, from 0 to 1.

`float audio_delay_node::decay;`

## Remarks:
0 makes no echoes, and values closer to 1 make more echoes that fade more slowly. A value of 1, which higher ones are treated as, makes echoes that never fade. If the node was created with a decay of 0, it is a plain delay, which gives the audio once, late by the delay, and this is then how loud each repetition after that is.
