# SysLog - To - CSV
This tool is designed to read syslog files and extract
the contents into a csv format. It uses regular expressions
to extract all data and sort it correctly into a Pandas
Dataframe. This was designed for personal use with my own
syslog files, so it may not work with all formats.

# Current features:
- command line interface
- reads in user and archived log files (.gz format)
- extracts data via regex and builds dataframe
- saves dataframe as csv
