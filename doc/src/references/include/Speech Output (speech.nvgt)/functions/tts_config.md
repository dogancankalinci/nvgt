# tts_config
Show a form for the user to choose the voice, rate and volume of a tts_voice, and whether a running screen reader is preferred.

`void tts_config(tts_voice@ v, bool main_config = false);`

## Arguments:
* tts_voice@ v: the voice to configure.
* bool main_config = false: true when v is the global tts voice of this include. Changes are then heard at once in the speech of the form itself, and the screen reader checkbox can be changed.

## Remarks:
Save applies only the settings that were changed, so the others keep following the system's settings; Cancel puts back what was changed while the form was open.
