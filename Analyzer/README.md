# BinTyper Analyzer
This IDAPython scripts analyzes the target binary and generates class information files.

# Requirements
- IDA 7.3

# Usage
Open a target binary and load the python script named `main.py` by IDAPython. Since It may takes **REALLY LONG** time to generate all results (Poor optimization + Single thread).

## Note
Following files will be generated by BinTyper Analyzer. These files are used by BinTyper Tracker for tracking/verification.
- `%TARGET_NAME%.image_base.bintyper`
- `%TARGET_NAME%.output_class_identifiers.bintyper.json`
- `%TARGET_NAME%.output_identifier_with_area_layouts.bintyper.json`
- `%TARGET_NAME%.output_identifier_with_constructors.bintyper.json`
- `%TARGET_NAME%.vft_set.bintyper.json`