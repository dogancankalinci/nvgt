# stream_pcm
Queues raw audio for the sound to play, starting a stream of it on the first call.

`bool sound::stream_pcm(const float[]@ data, uint sample_rate = 0, uint channels = 0, uint buffer_size = 0);`

## Arguments:
* const float[]@ data: the samples to queue, interleaved by channel. Arrays of int, int16 and uint8, and memory_buffers of these types, are taken as well. Samples past the last whole frame are dropped, and fewer than one frame is refused with AUDIO_ERROR_STATE_INVALID_ARGS.
* uint sample_rate = 0: the sample rate of the audio; 0 means the engine's on the first call, and the stream's after it.
* uint channels = 0: the number of channels of the audio; 0 means the engine's on the first call, and the stream's after it.
* uint buffer_size = 0: how many frames the stream's queue holds; 0 means twice the frames given. Only the first call's counts, as the queue can't be resized.

## Returns:
bool: true if the audio was queued, false otherwise.

## Remarks:
The first call closes whatever the sound had loaded, makes the queue and starts playing. Later calls must give the same sample type as the first, and any sample rate or channel count they give must be the stream's, or they are refused with AUDIO_ERROR_STATE_INVALID_ARGS.

When the queue is full, the call waits for the sound to play room free. It gives up with AUDIO_ERROR_STATE_TIMEOUT when nothing has made room for a second, having queued part of the audio. A sound that isn't playing, and a call from a processing callback, take all of the audio or none of it, refusing with AUDIO_ERROR_STATE_BUSY, or AUDIO_ERROR_STATE_TOO_BIG for more than the whole queue holds.
