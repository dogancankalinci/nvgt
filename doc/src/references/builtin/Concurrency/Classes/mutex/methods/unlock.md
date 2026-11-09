# unlock
Unlocks the mutex.

`void unlock();`

## Remarks:
This function does nothing if the mutex is already unlocked. Unlocking a mutex that another thread holds raises an exception, on every platform.
