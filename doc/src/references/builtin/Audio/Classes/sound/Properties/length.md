# length
Get the length of a sound, in milliseconds, or in frames when the sound's engine was made with AUDIO_ENGINE_DURATIONS_IN_FRAMES.

`uint64 sound::length;`

## Remarks:
A stream without a known length, such as one from stream_url() or stream_pcm(), reads 0.
