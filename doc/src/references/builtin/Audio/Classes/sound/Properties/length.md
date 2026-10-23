# length
Get the length of a sound, in milliseconds, or in frames when the sound's engine was made with AUDIO_ENGINE_DURATIONS_IN_FRAMES.

`uint64 sound::length;`

## Remarks:
A stream without a known length, such as one from stream_url() or stream_pcm(), reads 0.

A sound playing a chain of data sources, opened with open(), reads the length of the whole chain, from the source its head was on when it was opened, and play_looped() loops the whole chain; it reads 0 if any source's length is unknown or a later source in the chain links back so that the chain never ends. A single source linked to itself reads its own length.
