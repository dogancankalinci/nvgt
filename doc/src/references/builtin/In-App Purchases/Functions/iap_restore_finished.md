# iap_restore_finished
Check whether the operation started with iap_restore_purchases() has completed.

`bool iap_restore_finished();`

## Returns:
bool: true once the restore operation has finished, false while it is still in progress.

## Remarks:
This is the polling companion to iap_restore_purchases(). Once it returns true, retrieve any restored purchases with iap_get_pending_purchases().
