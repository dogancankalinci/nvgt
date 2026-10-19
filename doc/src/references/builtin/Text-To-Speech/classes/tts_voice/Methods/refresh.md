# refresh
Rebuilds the list of TTS voices this object knows about from the voices its engines report.

Each engine lists the voices it has now, so voices installed or removed while the program runs appear or go, and the voice numbers can change. An engine that has never started isn't tried again, and an engine installed while the program runs is only used on Android, once the user makes it the preferred engine. An engine that has worked but couldn't be started for this object, while it restarted for instance, is tried again. When the voice the script chose is no longer listed, the object goes back to the platform's voice, and voice_set turns false.

`bool tts_voice::refresh();`

## Returns:
bool: true if the list was successfully refreshed, false otherwise.
