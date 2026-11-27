# get_output_bus_volume
Get the volume of an output bus.

`float audio_node::get_output_bus_volume(uint bus);`

## Arguments:
* uint bus: the number of the bus, starting at 0.

## Returns:
float: the volume multiplier of the bus, or NaN for a bus the node doesn't have, with SOUNDSYSTEM_LAST_ERROR set to AUDIO_ERROR_STATE_INVALID_ARGS.
