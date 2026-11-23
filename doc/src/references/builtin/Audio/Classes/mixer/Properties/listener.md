# listener
The index of the listener that the mixer is heard from.

`const uint mixer::listener;`

## Remarks:
This is the pinned listener, listener 0 by default, and the listener closest to the mixer once `pinned_listener` is set to 255. Most games only have listener 0.
