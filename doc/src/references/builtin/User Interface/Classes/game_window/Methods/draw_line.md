# draw_line
Draw a line.

`void game_window::draw_line(float x1, float y1, float x2, float y2, uint r, uint g, uint b);`

## Arguments:
* float x1: the horizontal position of the start.
* float y1: the vertical position of the start.
* float x2: the horizontal position of the end.
* float y2: the vertical position of the end.
* uint r: the red component of the color, from 0 to 255.
* uint g: the green component of the color, from 0 to 255.
* uint b: the blue component of the color, from 0 to 255.

## Remarks:
A line with a coordinate that isn't finite (NaN or infinity) isn't drawn. Only the part of a line within 16777216 pixels of the origin is drawn, which is far past any window.
