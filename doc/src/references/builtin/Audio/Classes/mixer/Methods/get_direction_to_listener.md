# get_direction_to_listener
Get the direction from the mixer to the listener that it is heard from.

`vector@ mixer::get_direction_to_listener() const;`

## Returns:
vector@: a vector of length 1 pointing from the mixer towards the listener, or (0, 0, 0) if the mixer is at the listener's position.

## Remarks:
The direction is given as the listener sees it rather than in the coordinates of your game: x goes to the listener's right, y up and z backwards. A mixer straight ahead of the listener gives (0, 0, 1), as the listener is behind it, and one directly to the listener's right gives (-1, 0, 0).
