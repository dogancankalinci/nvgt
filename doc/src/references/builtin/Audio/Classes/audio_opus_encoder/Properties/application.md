# application
What the encoded audio will be used for, a value of the opus_application_type enum.

`int audio_opus_encoder::application;`

## Remarks:
The default is OPUS_APPLICATION_AUDIO. Set it before writing audio: it can be changed after `open()` until the encoder starts making packets, about 2 seconds of audio later, after which a change is refused, the property keeping its value, with SOUNDSYSTEM_LAST_ERROR set to AUDIO_ERROR_STATE_INVALID_ARGS.
