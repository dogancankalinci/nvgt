# set_looping
Set whether the source starts again from its loop point when it reaches its end.

`bool audio_data_source::set_looping(bool looping);`

## Arguments:
* bool looping: whether to loop.

## Returns:
bool: true if the setting was taken, also when it was already so. false if the source has nothing open, if it is read elsewhere now, by a sound playing it, a chain including it or the node its output is attached to, or, for looping, if it is a ring buffer or microphone, which can't loop.
