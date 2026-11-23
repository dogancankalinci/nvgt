# read
Retrieve rendered audio from the engine.

`float[]@ audio_engine::read(uint64 frame_count);`

## Arguments:
* uint64 frame_count: the number of frames to read, where a frame has one sample for each channel of the engine.

## Returns:
float[]@: the samples, interleaved by channel, as values between -1 and 1. This is `frame_count * channels` values long, silent where nothing played, even when nothing is playing at all; it is empty if the engine can't be read, see below.

## Remarks:
Every call advances the engine by the number of frames read, so reading 44100 frames from an engine with a sample rate of 44100 hertz gives and moves it forward by one second. This is how audio is retrieved from an engine created with AUDIO_ENGINE_NO_DEVICE. An engine with a device is read by its device, so reading it is refused with `SOUNDSYSTEM_LAST_ERROR` set to `AUDIO_ERROR_STATE_INVALID_OPERATION`, as is reading an engine attached into another engine, which reads it there.
