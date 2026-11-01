# processing_callback
A function the engine calls with each block of audio it mixed for its output device, which can read or change the block before the device plays it.

`audio_engine_processing_callback@ audio_engine::processing_callback;`

`funcdef void audio_engine_processing_callback(audio_engine@ engine, memory_buffer<float>& data, uint64 frames);`

## Remarks:
The function is called on the engine's device thread, not on the script's thread, once for each block the device asks for: data holds frames frames of the engine's output, interleaved in its channel count and silent where nothing played, even with nothing playing at all, which the device plays once the function returns. An engine made without a device never calls it. Setting it to null removes it.

The device waits for the function, so it should return quickly. An encoder's calls made from it don't wait for a script thread that is using the same encoder at that moment: they fail with AUDIO_ERROR_STATE_BUSY instead, as do a decoder's or other audio source's read(), open() and close(). Using the default engine from it, as sound_play() and sound() do, fails the same way while another thread is still making that engine; and before any thread has made it, it can't be made from the callback, so those calls throw there until a script thread uses the sound system, as reading sound_master_volume does. Moving a listener from it waits for any sounds a script thread is placing at that moment, which is brief.

The engine keeps the function it is given, and a function made from an object's method keeps that object. So an object that holds its engine and gives it one of its own methods is kept alive by the engine, and the engine by it, after the script lets go of the object: the engine keeps its device open and goes on calling the method. Set processing_callback to null before letting go of such an object.
