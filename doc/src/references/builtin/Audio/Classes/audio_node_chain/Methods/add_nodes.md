# add_nodes
Add several nodes to the end of the chain, in order.

`bool audio_node_chain::add_nodes(const audio_node@[]@ nodes);`

## Arguments:
* const audio_node@[]@ nodes: the nodes to add.

## Returns:
bool: true if every node was added, false if any was null or couldn't be connected, though the others are still added.

## Remarks:
Where it would make a path through the audio graph longer than the engine can read, 64 nodes (see mixer), it is refused with SOUNDSYSTEM_LAST_ERROR set to AUDIO_ERROR_STATE_TOO_BIG.
An initializer list can be passed directly, as in `chain.add_nodes({low_pass, echo});`. The `+=` operator does the same.
