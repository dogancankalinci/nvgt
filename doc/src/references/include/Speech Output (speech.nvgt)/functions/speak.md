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
Text longer than 10000 bytes is spoken in parts of at most 4096 bytes, cut at the last space past the first 2048 bytes, or where there is none, at the end of a character. When the screen reader turns the text down, as VoiceOver does while the game has no window in front, the tts voice speaks it.
