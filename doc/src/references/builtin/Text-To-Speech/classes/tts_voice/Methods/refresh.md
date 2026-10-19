# refresh
Rebuilds the list of TTS voices this object knows about from the voices its engines report.

Each engine lists the voices it has now, so voices installed or removed while the program runs appear or go, and the voice numbers can change. An engine that has never started isn't tried again. Engines installed while the program runs are used only on Android, once the user makes one of them the preferred engine, when every engine installed by then is added. An engine that has worked but couldn't be started for this object, while it restarted for instance, is tried again.

The object also makes its list again by itself, at its next use, when an engine reports that its installed voices may have changed: on Windows when the voices in the registry change, on Android when an app is installed, removed or updated, or the app's window has focus again after the user may have changed voices in an engine's settings, and on Apple platforms when Apple reports it, from iOS 17 and macOS 14 on, or before that when the app becomes active again. The voices of an Android engine whose app was removed leave the list then. When the voice the script chose is no longer listed, the object goes back to the platform's voice, and voice_set turns false, until a list holds that voice again (see voice_set).

`bool tts_voice::refresh();`

## Returns:
bool: true if the list was successfully refreshed, false otherwise.
