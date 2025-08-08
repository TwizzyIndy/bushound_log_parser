"""
BusHound Log Parser
Parses BusHound generated log files and extracts data based on Device ID and Phase type.
Creates binary dump files from the extracted hex data.


TwizzyIndy
08/2025
"""

import re
import sys
import argparse
from pathlib import Path
from typing import List, Dict, Optional


class BusHoundParser:
    def __init__(self, log_file_path: str):
        """
        Initialize the parser with a BusHound log file.
        
        Args:
            log_file_path: Path to the BusHound log file
        """
        self.log_file_path = Path(log_file_path)
        self.entries = []
        self.header_info = {}
        
    def parse_file(self, target_device_id: Optional[str] = None, target_phase: Optional[str] = None) -> bool:
        """
        Parse the BusHound log file and extract all entries.
        
        Args:
            target_device_id: Only parse entries for this device ID (for efficiency)
            target_phase: Only parse entries for this phase (for efficiency)
        
        Returns:
            True if parsing was successful, False otherwise
        """
        try:
            print(f"Opening file: {self.log_file_path}")
            with open(self.log_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            print(f"File loaded: {len(lines)} lines")
            
            # Find the start of data entries (after the header)
            data_start_idx = 0
            for i, line in enumerate(lines):
                if line.strip().startswith('Device  Phase  Data'):
                    data_start_idx = i + 2  # Skip the header and separator line
                    break
            
            if data_start_idx == 0:
                print("Error: Could not find data section in the log file")
                return False
            
            print(f"Data section starts at line {data_start_idx}")
            
            # Pre-compile regex patterns for efficiency
            device_pattern = re.compile(r'^\s*(\d+(?:\.\d+)?)\s+(IN|OUT)\s+([0-9a-fA-F\s]+)\s+.*?\s+(\d+\.\d+\.\d+(?:\(\d+\))?)\s*$')
            continuation_pattern = re.compile(r'^\s+([0-9a-fA-F\s]+)\s+.*?\s+(\d+\.\d+\.\d+)\s*$')
            
            # Parse each data entry
            current_entry = None
            processed_lines = 0
            total_lines = len(lines) - data_start_idx
            
            for line_num, line in enumerate(lines[data_start_idx:], start=data_start_idx):
                processed_lines += 1
                
                # Show progress every 10000 lines
                if processed_lines % 10000 == 0:
                    progress = (processed_lines / total_lines) * 100
                    print(f"Processing: {progress:.1f}% ({processed_lines}/{total_lines} lines)")
                
                if not line.strip():
                    continue
                
                # Check if this is a new entry (starts with device ID)
                device_match = device_pattern.match(line)
                if device_match:
                    device_id = device_match.group(1)
                    phase = device_match.group(2)
                    
                    # Save previous entry if exists
                    if current_entry and current_entry.get('matches_filter', True):
                        self.entries.append(current_entry)
                    
                    # Check if this entry matches target filters
                    matches_filter = True
                    if target_device_id and device_id != target_device_id:
                        matches_filter = False
                    if target_phase and phase.upper() != target_phase.upper():
                        matches_filter = False
                    
                    # Always create current_entry to track context for continuation lines
                    hex_data = device_match.group(3).replace(' ', '')
                    cmd_info = device_match.group(4)
                    
                    current_entry = {
                        'device_id': device_id,
                        'phase': phase,
                        'hex_data': hex_data,
                        'description': '',  # No description captured in simplified pattern
                        'cmd_info': cmd_info,
                        'line_number': line_num + 1,
                        'matches_filter': matches_filter  # Track if this entry should be included
                    }
                else:
                    # Check if this is a continuation line with hex data
                    hex_continuation = continuation_pattern.match(line)
                    if hex_continuation and current_entry:
                        additional_hex = hex_continuation.group(1).replace(' ', '')
                        continuation_cmd = hex_continuation.group(2)
                        
                        # Only process continuation if the main entry matches filters
                        if current_entry.get('matches_filter', True):
                            # For single-file dumping: append to current entry
                            # Only append to main entry if it doesn't have a repetition number
                            if '(' not in current_entry['cmd_info']:
                                current_entry['hex_data'] += additional_hex
                            
                            # For command-based dumping: create separate entry for this offset
                            offset_entry = {
                                'device_id': current_entry['device_id'],
                                'phase': current_entry['phase'],
                                'hex_data': additional_hex,
                                'description': '',  # continuation lines don't have meaningful description
                                'cmd_info': continuation_cmd,
                                'line_number': line_num + 1,
                                'matches_filter': True
                            }
                            # Add offset entry immediately to preserve order
                            self.entries.append(offset_entry)
            
            # Don't forget the last entry
            if current_entry and current_entry.get('matches_filter', True):
                self.entries.append(current_entry)
            
            # Clean up the matches_filter field from all entries
            for entry in self.entries:
                entry.pop('matches_filter', None)
            
            print(f"Successfully parsed {len(self.entries)} entries from {self.log_file_path}")
            return True
            
        except Exception as e:
            print(f"Error parsing file: {e}")
            return False
    
    def filter_entries(self, device_id: Optional[str] = None, phase: Optional[str] = None) -> List[Dict]:
        """
        Filter entries based on device ID and/or phase type.
        
        Args:
            device_id: Device ID to filter by (e.g., "7", "7.0")
            phase: Phase type to filter by ("IN" or "OUT")
        
        Returns:
            List of filtered entries
        """
        filtered = self.entries
        
        if device_id is not None:
            filtered = [entry for entry in filtered if entry['device_id'] == device_id]
        
        if phase is not None:
            phase = phase.upper()
            filtered = [entry for entry in filtered if entry['phase'] == phase]
        
        return filtered
    
    def dump_to_binary(self, entries: List[Dict], output_file: str) -> bool:
        """
        Dump hex data from entries to a binary file.
        
        Args:
            entries: List of entries containing hex data
            output_file: Path to output binary file
        
        Returns:
            True if successful, False otherwise
        """
        try:
            with open(output_file, 'wb') as f:
                total_bytes = 0
                for entry in entries:
                    hex_data = entry['hex_data']
                    if hex_data:
                        # Convert hex string to bytes
                        try:
                            # Ensure even number of hex characters
                            if len(hex_data) % 2 != 0:
                                hex_data = hex_data + '0'
                            
                            binary_data = bytes.fromhex(hex_data)
                            f.write(binary_data)
                            total_bytes += len(binary_data)
                        except ValueError as e:
                            print(f"Warning: Invalid hex data in entry at line {entry['line_number']}: {e}")
                            continue
                
                print(f"Successfully wrote {total_bytes} bytes to {output_file}")
                return True
                
        except Exception as e:
            print(f"Error writing binary file: {e}")
            return False
    
    def dump_to_binary_by_command(self, entries: List[Dict], output_dir: str = "output") -> bool:
        """
        Dump hex data from entries to separate binary files based on Cmd.Phase.
        Each unique Cmd.Phase gets its own file with data assembled by offset.
        
        Args:
            entries: List of entries containing hex data
            output_dir: Directory to save the binary files
        
        Returns:
            True if successful, False otherwise
        """
        try:
            # Create output directory if it doesn't exist
            Path(output_dir).mkdir(exist_ok=True)
            
            # Group entries by Cmd.Phase
            cmd_groups = {}
            for entry in entries:
                cmd_info = entry['cmd_info']
                # Extract Cmd.Phase from cmd_info (e.g., "8.1.0" -> "8.1")
                cmd_match = re.match(r'^(\d+\.\d+)\.(\d+)(?:\((\d+)\))?$', cmd_info)
                if cmd_match:
                    cmd_phase = cmd_match.group(1)  # e.g., "8.1"
                    offset = int(cmd_match.group(2))  # e.g., 0, 4, 8, 12, 16
                    rep = cmd_match.group(3)  # repetition number if present
                    
                    if cmd_phase not in cmd_groups:
                        cmd_groups[cmd_phase] = {}
                    
                    # Store entry with its offset (now main entries only contain their own data)
                    cmd_groups[cmd_phase][offset] = entry
            
            total_files = 0
            total_bytes = 0
            
            # Process each command group
            for cmd_phase, offset_entries in cmd_groups.items():
                # Sort by offset to ensure correct order
                sorted_offsets = sorted(offset_entries.keys())
                
                # Determine the device ID for filename
                first_entry = offset_entries[sorted_offsets[0]]
                device_id = first_entry['device_id']
                phase_type = first_entry['phase']
                
                # Create filename
                filename = f"dev{device_id}_{phase_type}_{cmd_phase}.bin"
                filepath = Path(output_dir) / filename
                
                # Assemble data by offset
                with open(filepath, 'wb') as f:
                    file_bytes = 0
                    current_offset = 0
                    
                    for offset in sorted_offsets:
                        entry = offset_entries[offset]
                        hex_data = entry['hex_data']
                        
                        if hex_data:
                            try:
                                # Ensure even number of hex characters
                                if len(hex_data) % 2 != 0:
                                    hex_data = hex_data + '0'
                                
                                # Add padding if there's a gap in offsets
                                if offset > current_offset:
                                    padding = b'\x00' * (offset - current_offset)
                                    f.write(padding)
                                    file_bytes += len(padding)
                                    current_offset = offset
                                
                                binary_data = bytes.fromhex(hex_data)
                                f.write(binary_data)
                                file_bytes += len(binary_data)
                                current_offset += len(binary_data)
                                
                            except ValueError as e:
                                print(f"Warning: Invalid hex data in {filename} at offset {offset}: {e}")
                                continue
                    
                    print(f"Created {filename}: {file_bytes} bytes")
                    total_files += 1
                    total_bytes += file_bytes
            
            print(f"\nSuccessfully created {total_files} binary files with {total_bytes} total bytes in {output_dir}/")
            return True
            
        except Exception as e:
            print(f"Error creating binary files: {e}")
            return False
    
    def print_entries_summary(self, entries: List[Dict]) -> None:
        """
        Print a summary of the filtered entries.
        
        Args:
            entries: List of entries to summarize
        """
        if not entries:
            print("No entries found matching the criteria.")
            return
        
        print(f"\nFound {len(entries)} matching entries:")
        print("-" * 80)
        print(f"{'Line':>6} {'Device':>8} {'Phase':>6} {'Bytes':>6} {'Description':>20}")
        print("-" * 80)
        
        total_bytes = 0
        for entry in entries:
            hex_len = len(entry['hex_data']) // 2 if entry['hex_data'] else 0
            total_bytes += hex_len
            desc = entry['description'][:18] + '...' if len(entry['description']) > 20 else entry['description']
            print(f"{entry['line_number']:>6} {entry['device_id']:>8} {entry['phase']:>6} {hex_len:>6} {desc:>20}")
        
        print("-" * 80)
        print(f"Total bytes: {total_bytes}")


def main():
    parser = argparse.ArgumentParser(
        description='Parse BusHound log files and extract data based on Device ID and Phase',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python bushound_parser.py -f ReadInfo_BusHound.txt -d 7 -p IN -o device7_in.bin
  python bushound_parser.py -f ReadInfo_BusHound.txt -d 7.0 -p OUT -o device7_out.bin
  python bushound_parser.py -f ReadInfo_BusHound.txt -d 44 -o device44_all.bin
  python bushound_parser.py -f ReadInfo_BusHound.txt -p IN -o all_in.bin
  python bushound_parser.py -f ReadInfo_BusHound.txt -d 7 --by-command -o output_dir/
        """
    )
    
    parser.add_argument('-f', '--file', required=True,
                       help='Path to BusHound log file')
    parser.add_argument('-d', '--device-id', 
                       help='Device ID to filter by (e.g., "7", "7.0", "44")')
    parser.add_argument('-p', '--phase', choices=['IN', 'OUT', 'in', 'out'],
                       help='Phase type to filter by (IN or OUT)')
    parser.add_argument('-o', '--output',
                       help='Output binary file path or directory (required if dumping data)')
    parser.add_argument('-s', '--summary', action='store_true',
                       help='Show summary of filtered entries without dumping')
    parser.add_argument('--by-command', action='store_true',
                       help='Create separate binary files for each Cmd.Phase combination')
    
    args = parser.parse_args()
    
    # Validate arguments
    if not args.summary and not args.output:
        print("Error: Either --output or --summary must be specified")
        return 1
    
    if not Path(args.file).exists():
        print(f"Error: File '{args.file}' does not exist")
        return 1
    
    # Initialize parser and parse file
    bush_parser = BusHoundParser(args.file)
    # Pass target filters to make parsing more efficient for large files
    if not bush_parser.parse_file(
        target_device_id=args.device_id,
        target_phase=args.phase.upper() if args.phase else None
    ):
        return 1
    
    # Filter entries
    filtered_entries = bush_parser.filter_entries(
        device_id=args.device_id,
        phase=args.phase.upper() if args.phase else None
    )
    
    # Show summary
    bush_parser.print_entries_summary(filtered_entries)
    
    # Dump to binary file(s) if requested
    if args.output and filtered_entries:
        if args.by_command:
            # Create separate files for each command
            if bush_parser.dump_to_binary_by_command(filtered_entries, args.output):
                print(f"\nBinary files successfully created in: {args.output}")
            else:
                return 1
        else:
            # Create single combined file
            if bush_parser.dump_to_binary(filtered_entries, args.output):
                print(f"\nBinary data successfully dumped to: {args.output}")
            else:
                return 1
    elif args.output and not filtered_entries:
        print("No data to dump - no entries matched the filter criteria")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())
