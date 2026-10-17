# refresh
Rebuilds the list of TTS voices this object knows about from the voices its engines report.

Engines on Android and Apple platforms report the voices they found when they were first used, and an engine that has never started isn't tried again, so voices installed while the program runs don't appear there. An engine that has worked but couldn't be started for this object, while it restarted for instance, is tried again. When the voice the script chose is no longer listed, the object goes back to the platform's voice, and voice_set turns false.

`bool tts_voice::refresh();`

## Returns:
bool: true if the list was successfully refreshed, false otherwise.
