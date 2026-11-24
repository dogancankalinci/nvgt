# q
The slope of the shelf, how sharp its transition is.

`double audio_low_shelf_filter::q;`

## Remarks:
Higher values make the transition sharper. The default of 0.707 gives a smooth, natural response. How high it can go depends on the gain: a slope that, with the gain, can't make a stable shelf is refused, leaving the filter as it was and setting `SOUNDSYSTEM_LAST_ERROR`, around 17 for a gain of 6 decibels and 2.3 for 20; a gain that can't be had at the current slope is refused the same way.
