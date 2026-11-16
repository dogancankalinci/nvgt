# timestamp
Stores a unix timestamp with microsecond accuracy and provides methods for comparing them.
1. timestamp();
2. timestamp(int64 epoch_microseconds);

## Arguments 2:
* int64 epoch_microseconds: the initial value of the timestamp

## Remarks:
If a timestamp object is initialize with the default constructor, it will be set to the system's current date and time.
The unix epoch began on January 1st, 1970 at 12 AM UTC.
Adding to, subtracting from and taking the difference of timestamps stops at the largest or smallest value an int64 can hold rather than wrapping around to the other end. A timestamp more than about 29000 years before or after 1970 has no UTC time that fits in an int64: its UTC_time property stops at the int64 limit, and making a datetime or calendar from it, or formatting it, raises an "Invalid date/time." exception.
