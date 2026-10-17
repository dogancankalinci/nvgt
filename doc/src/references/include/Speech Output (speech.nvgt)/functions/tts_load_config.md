# tts_load_config
Apply settings written by tts_dump_config to a tts_voice.

`bool tts_load_config(string config, tts_voice@ v);`

## Arguments:
* string config: the string tts_dump_config returned.
* tts_voice@ v: the voice to apply the settings to.

## Returns:
bool: true if the string held settings, false if it had too few parts.

## Remarks:
The voice is chosen by its name and language, or by its name alone when it was saved without a language, and left as it was when no such voice is listed now or the name is "default"; an empty rate or volume is left as it was too. use_sr is set too when the string has it.
