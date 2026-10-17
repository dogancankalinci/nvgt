# Speech output
speech.nvgt speaks through the user's screen reader when one is running and through a text-to-speech voice otherwise, and gives the user a form to configure that voice. It includes form.nvgt.

## Global variables:
* tts_voice tts: the voice used when no screen reader speaks.
* bool use_sr = true: whether a running screen reader is preferred over the tts voice.
* bool tts_default_interrupt = true: whether speak interrupts the speech before it when told nothing else.
* text_processing_callback@ tts_default_text_processing_callback = null: a function speak runs the text through before speaking it, when told no other. Its signature is `string text_processing_callback(const string&in text)`.
* string speechbuff: the last text given to speak, before any processing, for a key that repeats it.
* audio_form@ tts_config_form: the form tts_config shows with main_config set, while it is open; null otherwise.

## Functions besides those below:
* `void raw_speak(string text, bool interrupt)`: what speak does for each part, without processing, braille or splitting.
* `string[] tts_voice_display_names(tts_voice@ v)`: the voices' names as tts_config shows them, with the language added to a name another voice also has.
