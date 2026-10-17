# tts_dump_config
Write the settings of a tts_voice to a string, to save and load later with tts_load_config.

`string tts_dump_config(tts_voice@ v, bool save_screen_reader_setting = false);`

## Arguments:
* tts_voice@ v: the voice whose settings to write.
* bool save_screen_reader_setting = false: whether to write use_sr too.

## Returns:
string: the voice's name, rate and volume, separated by "||".
