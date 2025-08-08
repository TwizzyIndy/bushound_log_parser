# BusHound Log Parser

This allows you to parse BusHound generated log files and extract data based on Device ID and Phase number, then dump the raw binary data to files.

## Files Included

1. **`bushound_parser.py`** - Command-line version with full features

## Features

- Parse BusHound log files (.txt format)
- Filter data by Device ID (e.g., "7", "7.0", "44")
- Filter data by Phase type ("IN" or "OUT")
- Extract hex data from the Data column
- Convert hex data to raw binary format
- Dump filtered data to binary files
- Show summary statistics of filtered entries

## Usage

### Command Line Version

#### Basic Examples:

```bash
# Show help
python bushound_parser.py --help

# Show summary of all entries in the log file
python bushound_parser.py -f ReadInfo_BusHound.txt -s

# Extract all data from Device ID 7 and save to binary file
python bushound_parser.py -f ReadInfo_BusHound.txt -d 7 -o device7_all.bin

# Extract only IN phase data from Device ID 7
python bushound_parser.py -f ReadInfo_BusHound.txt -d 7 -p IN -o device7_in.bin

# Extract only OUT phase data from Device ID 7
python bushound_parser.py -f ReadInfo_BusHound.txt -d 7 -p OUT -o device7_out.bin

# NEW: Extract data by command - creates separate files for each Cmd.Phase
python bushound_parser.py -f ReadInfo_BusHound.txt -d 43.0 --by-command -o device43_commands/

# Extract all data from Device ID 44 (e.g., Samsung Mobile device)
python bushound_parser.py -f ReadInfo_BusHound.txt -d 44 -o device44_all.bin

# Extract all IN phase data from all devices
python bushound_parser.py -f ReadInfo_BusHound.txt -p IN -o all_in_data.bin

# Extract all OUT phase data from all devices
python bushound_parser.py -f ReadInfo_BusHound.txt -p OUT -o all_out_data.bin
```

#### Command Line Arguments:

- `-f, --file`: Path to BusHound log file (required)
- `-d, --device-id`: Device ID to filter by (optional)
- `-p, --phase`: Phase type to filter by (IN or OUT, optional)
- `-o, --output`: Output binary file path or directory (required for dumping)
- `-s, --summary`: Show summary without dumping data
- `--by-command`: Create separate binary files for each Cmd.Phase combination

## Command-Based Dumping

The `--by-command` option creates separate binary files for each unique `Cmd.Phase` combination found in the log. This is perfect for analyzing individual USB transactions.

### How it works:

For example, if you have entries like:
```
   43.0  OUT    98 4d 64 07  .Md.                   128.1.0        
               00 00 00 00  ....                   128.1.4        
               b3 0a 26 57  ..&W                   128.1.8        
               c3 0d 68 57  ..hW                   128.1.12       
```

This creates a file `dev43.0_OUT_128.1.bin` containing all the hex data assembled by offset:
- Offset 0: `98 4d 64 07`
- Offset 4: `00 00 00 00`  
- Offset 8: `b3 0a 26 57`
- Offset 12: `c3 0d 68 57`

The final binary file contains: `98 4d 64 07 00 00 00 00 b3 0a 26 57 c3 0d 68 57`

### Benefits:
- **Individual transaction analysis**: Each USB command/response is in its own file
- **Proper offset handling**: Data is assembled in the correct order based on offsets
- **Clean organization**: Files are named with device ID, phase, and command number
- **Reverse engineering friendly**: Perfect for analyzing protocol commands separately

## BusHound Log Format

The parser expects BusHound log files with the following format:

```
Device  Phase  Data         Description       Cmd.Phase.Ofs(rep)
------  -----  -----------  ----------------  ------------------
   7.0  IN     01 01 01 00  ....                     1.1.0
   7.0  IN     01 01 00 00  ....                     2.1.0
   7    OUT    00 00 00     ...                      3.1.0
   44   IN     12 34 56 78  .4Vx                     4.1.0
               9A BC DE F0  ....                     4.1.4
```

## Output

### Summary Output

When using the summary option (`-s`), you'll see:

```
Found 150 matching entries:
--------------------------------------------------------------------------------
  Line   Device  Phase  Bytes         Description
--------------------------------------------------------------------------------
    10      7.0     IN     18      ....
    12      7.0     IN      4      ....
    14        7    OUT      3      ...
    16        7    OUT      3      ...
    18      7.0     IN      4      ....
--------------------------------------------------------------------------------
Total bytes: 1024
```

### Binary Output

The binary files contain the raw hex data converted to binary format. Each entry's hex data is concatenated in the order they appear in the log file.

## Device ID Examples

Common Device IDs you might see in BusHound logs:

- `7`, `7.0` - USB Root Hub
- `44` - Samsung Mobile USB Composite Device
- `45` - Samsung Mobile USB Modem
- `9` - USB Composite Device

## Error Handling

The parser includes error handling for:

- Invalid hex data (warnings are shown but parsing continues)
- Missing or corrupted log files
- Invalid Device IDs or Phase types
- File I/O errors

## Requirements

- Python 3.6 or higher
- No external dependencies required (uses only standard library)

## Troubleshooting

1. **"No entries found"**: Check that your log file has the correct BusHound format
2. **"Invalid hex data"**: Some entries might have malformed hex strings (warnings will be shown)
3. **Large files**: The parser can handle large log files but may take time to process
4. **File encoding**: The parser uses UTF-8 with error ignoring for compatibility
