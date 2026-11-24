# close
Finish encoding, writing anything still waiting and completing the file.

`bool audio_encoder::close();`

## Returns:
bool: true if the encoder was closed with everything written, false if nothing was open, or if writing out what was waiting failed, in which case the encoder is closed all the same and `SOUNDSYSTEM_LAST_ERROR` tells why.

## Remarks:
A file isn't complete until the encoder is closed, so close it before using the file. This also happens when the encoder is destroyed.
