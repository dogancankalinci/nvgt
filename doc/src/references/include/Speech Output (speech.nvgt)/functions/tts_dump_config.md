# tts_dump_config
Write the settings of a tts_voice to a string, to save and load later with tts_load_config.

`string tts_dump_config(tts_voice@ v, bool save_screen_reader_setting = false);`

## Arguments:
* tts_voice@ v: the voice whose settings to write.
* bool save_screen_reader_setting = false: whether to write use_sr too.

## Returns:
string: "name||rate||0||volume", with "||1" or "||0" after it for use_sr when save_screen_reader_setting is true. Only what was set on the voice is written: the name is "default" and the rate or volume field empty for what still follows the system's settings, so it keeps following them after loading. The name has the voice's language in parentheses after it, when the voice reports one, so that the same voice is found again when another voice has the same name, as on Apple platforms, which list some voices once per language under one name; the 0 stands for a pitch, which isn't saved.
