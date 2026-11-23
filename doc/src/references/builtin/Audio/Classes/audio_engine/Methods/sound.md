# sound
Create a new, empty sound that belongs to this engine.

`sound@ audio_engine::sound();`

## Returns:
sound@: the new sound.

## Remarks:
`sound()` on its own makes a sound of the default engine, so this is how a sound of another engine is made. Load something into it with `sound::load()`.
