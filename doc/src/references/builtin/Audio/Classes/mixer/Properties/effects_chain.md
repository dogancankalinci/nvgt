# effects_chain
A chain of effects that the mixer's audio goes through before it is spatialized.

`const audio_node_chain@ mixer::effects_chain;`

## Remarks:
It is null where it can't be made, as where the audio graph is as deep as it can go (see mixer), with SOUNDSYSTEM_LAST_ERROR set to AUDIO_ERROR_STATE_TOO_BIG.
Add nodes such as filters to this with its `add_node()` method to apply them to everything in the mixer. The chain is created the first time it is accessed, so a mixer without effects costs nothing for it. Effects on a mixer process the mixed audio of all of its sounds at once, which is far cheaper than giving each sound the same effect.
