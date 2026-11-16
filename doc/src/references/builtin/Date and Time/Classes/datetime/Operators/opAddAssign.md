# opAddAssign
Add a duration represented as a timespan to a datetime object.
`datetime& opAddAssign(const timespan&in);`

A timespan longer than the whole range of valid dates (about 15000 years) raises an "Invalid date/time." exception, and so does a result outside the valid dates.
