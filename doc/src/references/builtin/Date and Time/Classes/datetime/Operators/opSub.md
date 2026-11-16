# opSub
1. Return a new datetime object with a duration of time represented as a timespan subtracted from it.
2. Return a duration represented by a timespan by subtracting 2 datetime objects from each other.
1. `datetime opSub(const timespan&in);`
2. `timespan opSub(const datetime&in);`

In the first form, a timespan longer than the whole range of valid dates (about 15000 years) raises an "Invalid date/time." exception, and so does a result outside the valid dates.
