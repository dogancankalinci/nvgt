# stop
Stop playing the mixer.

`bool mixer::stop();`

## Returns:
bool: true if the mixer was stopped, false otherwise.

## Remarks:
Everything in a stopped mixer is silent and held where it is until the mixer is played again, though the sounds in it still count as playing. Stopping a sound also moves it back to its start, use `sound::pause()` to keep its position.
