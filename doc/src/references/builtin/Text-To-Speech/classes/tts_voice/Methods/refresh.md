# refresh
Rebuilds the list of TTS voices this object knows about from the voices its engines report.

Engines on Android and Apple platforms report the voices they found when they were first used, and an engine that couldn't be started isn't tried again, so voices installed while the program runs don't appear there.

`bool tts_voice::refresh();`

## Returns:
bool: true if the list was successfully refreshed, false otherwise.
