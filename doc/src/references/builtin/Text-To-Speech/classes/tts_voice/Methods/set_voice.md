# set_voice
Set the voice of the TTS voice.

`bool tts_voice::set_voice(int index);`

## Arguments:
* int index: index of the voice to switch to.

## Returns:
bool: true if the voice was successfully set, false otherwise.

## Remarks:
Speech the object started with the previous voice goes on playing, and speech with the new voice follows it, also when the new voice belongs to another engine; see speak.
