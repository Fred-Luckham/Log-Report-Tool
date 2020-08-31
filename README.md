# Log-Report-Tool
A tool written in Python that reads log files and uses Regex searches to compile reports based on user parameters

## Current features:
- Reads from files from the user input path
- reads each line and searches for user input(ie. date, time..) and adds lines to array
- If input is found then a regex is performed
- Regex search scans for Protocol, Source, and Destination
- Outputs a text file formatted to display the hitcount of results

## Planned features:
- Check for format of file
- Handle mutliple files / paths
- Compile more indepth reports and plot data to graphics
- Handle many data formats
- Deploy as a Django application
