# playing
Determine if the sound is currently playing.

`bool sound::playing;`

## Remarks:
An engine mixes its sounds 512 frames at a time, and playing turns false once the block in which the sound ended is mixed, while its last frames can still be in that block. On a device that is a few milliseconds before they are heard. On an engine without a device that the script reads with audio_engine.read(), a read of a number of frames that isn't a multiple of 512 can leave up to 511 of them for the next read, so a loop that reads while playing is true should read once more, or read multiples of 512, to get the whole sound.
