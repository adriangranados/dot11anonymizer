# dot11anonymizer

This is a Python script that anonymizes 802.11 Layer 2 information found in capture files. It supports the following 802.11 Layer 2 identifiable fields:

- MAC addresses (OUIs are preserved)
- SSID
- Alcatel, Arista, Aruba, Cisco, Extreme Networks, Fortinet, MikroTik/Routerboard, Mist, Ruckus, and Zebra AP names (if present)
- HESSID (Hotspot 2.0)
- P2P Device ID (Wi-Fi Alliance P2P Specification)
- Device Name (WiFi Protected Setup)
- Model and serial number (Fortinet APs)

![Original vs. Anonymized Capture File](../master/dot11anonymizer-example.png "Original vs. Anonymized Capture File")

## Requirements

You need Python3 and [Scapy](https://github.com/secdev/scapy).

## Usage

```bash
python dot11anonymizer.py <input_file> [<input_file> ...]
```
where ```<input_file>``` is a capture file that contains 802.11 frames with [Radiotap](http://www.radiotap.org/) headers.

The script generates a copy of the file ending with the suffix ```-anonymized.pcap``` in the same location as the original file.

For example:

```bash
python dot11anonymizer.py ~/Desktop/mycapture.pcap
```
generates ```~/Desktop/mycapture-anonymized.pcap```

## Notes

Since modifications to the frame will result in a different frame checksum, the script automatically fixes the FCS field for frames that originally had a good FCS. For frames that originally had a bad FCS, the script will set the FCS field to ```0x00000000``` to ensure that the FCS remains bad after any modifications.
