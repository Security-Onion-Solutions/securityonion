# Localfile

## Description
Utilize a local CSV file (or multiple) for associating a value to contextual data.

## Configuration Requirements

``file_path`` - Path(s) used for CSV files containing associative data. CSV files can be dropped in the analyzer directory, with ``file_path`` specified like ``mycsv.csv``.

- The value in the first column is used for matching
- Header information should be supplied, as it is used for dynamically creating result sets
- Matches will be aggregated from the provided CSV files

The content of the CSV file(s) should be similar to the following:

Ex.

```
MatchValue,MatchDescription,MatchReference
abcd1234,ThisIsADescription,https://siteabouthings.abc
```

The ``file_path`` value(s) should be set in the ``sensoroni`` pillar, like so:

```
sensoroni:
  analyzers:
    localfile:
      file_path:
        - $file_path1
        - $file_path2
```
