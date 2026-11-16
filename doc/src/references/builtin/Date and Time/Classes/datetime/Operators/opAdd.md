# opAdd
Return a new datetime object with a duration of time represented as a timespan added to it.
`datetime opAdd(const timespan&in);`

A timespan longer than the whole range of valid dates (about 15000 years) raises an "Invalid date/time." exception, and so does a result outside the valid dates.
