# datasource
The audio_data_source that the sound is playing from, or null if nothing is loaded.

`audio_data_source@ sound::datasource;`

## Remarks:
The sound and its data source share the same audio, so reading details from either gives the same answers, and the same object is returned every time.

The data source of a sound can only be read through this property, such as for its cursor, length, range, loop point or format. The audio thread reads it whenever the sound plays, so while the sound uses it, every call that changes it or takes audio from it, such as `set_loop_point()`, `set_range()`, `set_next()`, `set_looping()`, `seek_frames()`, `read()` and `skip_frames()`, is refused, with `SOUNDSYSTEM_LAST_ERROR` set to `AUDIO_ERROR_STATE_INVALID_OPERATION`. Change the sound through its own methods and properties instead, such as `seek()` and `looping`. To give a sound loop points, a range or a chain of sources, set them on an audio_decoder and then play it with `sound::open()`. To analyse audio without disturbing a sound, open the file separately with an audio_decoder.
