# time
The node's local clock.

`const uint64 audio_node::time;`

## Remarks:
This counts the time the node has processed, and can be set with `set_time()`. For effects and other nodes it is in PCM frames. For sounds and mixers it is in the engine's unit of time, milliseconds unless the engine was made with AUDIO_ENGINE_DURATIONS_IN_FRAMES, in which case it is in frames. For the audio_engine it is instead the engine's global clock, in the same unit.
