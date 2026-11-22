# playing
Whether the mixer is playing.

`const bool mixer::playing;`

## Remarks:
A mixer is playing as soon as it is created, and stops when `stop()` is called. For a sound, this is whether the sound itself is playing, which becomes false when it reaches its end unless it is looping. A sound in a stopped mixer still counts as playing, though it is held where it is until the mixer is played again.
