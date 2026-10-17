# tts_config
Show a form for the user to choose the voice, rate and volume of a tts_voice, and whether a running screen reader is preferred.

`void tts_config(tts_voice@ v, bool main_config = false);`

## Arguments:
* tts_voice@ v: the voice to configure.
* bool main_config = false: true when v is the global tts voice of this include. The screen reader checkbox can then be changed, and while the tts voice speaks the form, because the box is unchecked or no screen reader is running, changes are heard at once in the speech of the form itself, which another voice with the form's settings speaks once they differ from v's, so v itself changes only on Save.

## Remarks:
Save applies only the settings that were changed, so the others keep following the system's settings; Cancel leaves v as it was, including the settings that were never set on it, and the screen reader checkbox too.
