# set_size_dpi
Change the size of the font for a display resolution.

`bool text_font::set_size_dpi(float ptsize, int hdpi, int vdpi);`

## Arguments:
* float ptsize: the new size in points.
* int hdpi: the horizontal resolution in dots per inch.
* int vdpi: the vertical resolution in dots per inch.

## Returns:
bool: true on success, false otherwise.

## Remarks:
A resolution of 0 takes the other one, and 0 for both keeps the font's current resolution. A size of more than 65535 pixels per em (the size in points times the larger resolution, divided by 72) is refused: the font engine can't render it.
