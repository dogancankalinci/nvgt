# read
Retrieve rendered audio from the engine.

`float[]@ audio_engine::read(uint64 frame_count);`

## Arguments:
* uint64 frame_count: the number of frames to read, where a frame has one sample for each channel of the engine.

## Returns:
float[]@: the samples, interleaved by channel, as values between -1 and 1. This is `frame_count * channels` values long, silent where nothing played, even when nothing is playing at all; it is empty if the engine can't be read, see below, or its endpoint is stopped with `set_state()`.

## Remarks:
The engine mixes its audio 512 frames at a time, and its clock moves on by whole blocks: reading 44100 frames from an engine with a sample rate of 44100 hertz gives one second of audio, and moves the clock to the end of the block those frames end in, up to 511 frames further, whose rest the next read gives first. This is how audio is retrieved from an engine created with AUDIO_ENGINE_NO_DEVICE. An engine with a device is read by its device, so reading it is refused with `SOUNDSYSTEM_LAST_ERROR` set to `AUDIO_ERROR_STATE_INVALID_OPERATION`, as is reading an engine attached into another engine, which reads it there.
