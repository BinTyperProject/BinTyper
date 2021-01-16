# BinTyper Tracker
It tracks accessed area information. It performs `Runtime Type Analysis` and `Verification` steps of BinTyper.

# Build environment
- OS: `Ubuntu 18.04 x64`
- Intel Pin version:  `pin-3.13-98189`

# Usage
It supports two modes: `Tracking` and `Verificadtion`.
## Tracking
`pin -t %SOME_PATH%/BinTyperTracker.so -i %TARGET_NAME% -m track -o %OUTPUT_FILE_NAME% -- %ARGUMENTS%`
### Example
`../pin -t ../source/tools/BinTyperTracker/obj-intel64/BinTyperTracker.so -i pdfium_test -m track -o result -- ~/repo/pdfium/out/release/pdfium_test ~/test1.pdf`

## Verification
`pin -t %SOME_PATH%/BinTyperTracker.so -i %TARGET_NAME% -m verify -o %OUTPUT_FILE_NAME% -- %ARGUMENTS%`
### Example
`../pin -t ../source/tools/BinTyperTracker/obj-intel64/BinTyperTracker.so -i pdfium_test -m verify -o result -- ~/repo/pdfium/out/release/pdfium_test ~/test2.pdf`

## Note
Both `Tracking` and `Verificadtion` requires preprocessed information files from BinTyper Analyzer. Target binariy have to be analyzed by the analyzer and the analyzer generates preprocessed information files. Following files are generated:
- `%TARGET_NAME%.image_base.bintyper`
- `%TARGET_NAME%.output_class_identifiers.bintyper.json`
- `%TARGET_NAME%.output_identifier_with_area_layouts.bintyper.json`
- `%TARGET_NAME%.output_identifier_with_constructors.bintyper.json`
- `%TARGET_NAME%.vft_set.bintyper.json`

Please note that the `%TARGET_NAME%.typed_instruction_information.bintyper.json` file is generated by `Tracking` mode of BinTyper Tracker. This file stores information of `Runtime Area Information`. The `Verification` mode uses this file to verify the typecasting safety.