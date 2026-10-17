# tts_load_config
Apply settings written by tts_dump_config to a tts_voice.

`bool tts_load_config(string config, tts_voice@ v);`

## Arguments:
* string config: the string tts_dump_config returned.
* tts_voice@ v: the voice to apply the settings to.

## Returns:
bool: true if the string held settings, false if it had too few parts.

## Remarks:
The voice is chosen by name, and left as it was when no voice of that name is installed now. use_sr is set too when the string has it.
