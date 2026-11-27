# add_node
Insert a node into the chain.

1. `bool audio_node_chain::add_node(audio_node@ node, audio_node@ after = null, uint input_bus_index = 0);`
2. `bool audio_node_chain::add_node(audio_node@ node, int after, uint input_bus_index = 0);`

## Arguments:
* audio_node@ node: the node to insert.
* audio_node@ after (1): the node in the chain to insert it after, or null to add it to the end of the chain.
* int after (2): the index of the node to insert it after, or -1 to insert it at the start.
* uint input_bus_index = 0: the input bus of the new node that the node before it, or the chain's input if it is the first, is attached to.

## Returns:
bool: true if the node was inserted, false if it is null, if `after` is not in the chain or is out of range, or if the connections could not be made.

## Remarks:
Where it would make a path through the audio graph longer than the engine can read, 64 nodes (see mixer), it is refused with SOUNDSYSTEM_LAST_ERROR set to AUDIO_ERROR_STATE_TOO_BIG.
Calling `add_node(node)` without saying where adds the node to the end of the chain, so nodes added that way are in the order they were added in. Pass -1 as the index to insert a node at the start.

The chain keeps a reference to the node for as long as it is in it.
