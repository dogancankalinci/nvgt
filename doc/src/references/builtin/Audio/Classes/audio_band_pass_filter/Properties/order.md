# order
How steeply the filter cuts frequencies beyond its cutoff, an even number from 2 to 8.

`uint audio_band_pass_filter::order;`

## Remarks:
Each step of order makes the cut on either side about 3 decibels per octave steeper, as each pair of orders adds a band-pass section of about 6 decibels per octave, so 2 is a gentle filter of about 6 decibels per octave and 8 a sharp one of about 24. Higher orders cost a little more processing. The order is chosen when the filter is created, where values above 8 are treated as 8, and can't be changed afterwards: setting this leaves it as it was and sets `SOUNDSYSTEM_LAST_ERROR`.
