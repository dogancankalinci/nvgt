# speak
Speak text through the user's screen reader, or through the tts voice when no screen reader is running or use_sr is false.

`bool speak(string text, bool interrupt = tts_default_interrupt, text_processing_callback@ processing_callback = tts_default_text_processing_callback, bool braille = true);`

## Arguments:
* string text: the text to speak.
* bool interrupt = tts_default_interrupt: whether to interrupt what is being spoken.
* text_processing_callback@ processing_callback = tts_default_text_processing_callback: a function to run the text through first, or null.
* bool braille = true: whether to also show the text on a braille display.

## Returns:
bool: always true.

## Remarks:
Text longer than 10000 characters is spoken in parts of about 4000 characters, cut at spaces.
