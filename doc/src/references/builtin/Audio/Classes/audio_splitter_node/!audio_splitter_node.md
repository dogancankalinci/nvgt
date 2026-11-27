# audio_splitter_node
A node that sends the audio it receives to two outputs, so that it can be processed in two different ways at once.

`audio_splitter_node(audio_engine@ engine = sound_default_engine, int channels = 0);`

## Arguments:
* audio_engine@ engine = sound_default_engine: the engine to create the node in.
* int channels = 0: the number of channels of the audio, or 0 (or a negative number) for the engine's number of channels.

## Remarks:
A channel count the engine can't make a node of is refused and the constructor throws, with SOUNDSYSTEM_LAST_ERROR set.
This is an audio_node with one input bus and two output buses, and has all of the methods and properties of audio_node. Both output buses carry a copy of the input, and their volumes can be set independently with `set_output_bus_volume()`.

A typical use is sending a sound both straight to the speakers and to an effect such as a reverb, which is how `reverb3d::create_attachment()` works.
