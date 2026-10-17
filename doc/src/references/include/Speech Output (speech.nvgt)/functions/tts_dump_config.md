# tts_dump_config
Write the settings of a tts_voice to a string, to save and load later with tts_load_config.

`string tts_dump_config(tts_voice@ v, bool save_screen_reader_setting = false);`

## Arguments:
* tts_voice@ v: the voice whose settings to write.
* bool save_screen_reader_setting = false: whether to write use_sr too.

## Returns:
string: "name||rate||0||volume", with "||1" or "||0" after it for use_sr when save_screen_reader_setting is true. The name is "default" when the voice can't say which voice it speaks with, and has the voice's language in parentheses after it when another voice has the same name; the 0 stands for a pitch, which isn't saved.
