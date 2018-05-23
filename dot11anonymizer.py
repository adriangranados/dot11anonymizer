#
# dot11anonymizer.py
# This script anonymizes 802.11 Layer 2 information found in capture files.
# Version 1.0
#
# Copyright (c) 2017 Adrian Granados. All rights reserved.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Notes:
# - It only supports captures using Radiotap as the data-link type.
# - It anonymizes MAC addresses (OUIs are preserved), SSID, device name (if present) 
#   and other identifiable fields found in the WPS, Interworking (Hotspot 2.0) 
#   and Wi-Fi Alliance P2P information elements.
#

import binascii
import struct
import zlib
from scapy.all import *

addr_map     = {} # map of anonymized MAC addresses

ssid_map     = {} # map of anonymized SSIDs
ssid_num     = 0  # counter to suffix anonymized SSIDs

dev_name_map = {} # map of anonymized device names
dev_name_num = 0  # counter to suffix anonymized device names

def anonymize_address(addr):

    global addr_map

    anonymized_addr = addr

    if addr:
        if addr != 'ff:ff:ff:ff:ff:ff':
            anonymized_addr = addr_map.get(addr)
            if not anonymized_addr:
                anonymized_addr = addr[:8] + \
                                  ":%02x" % (random.randint(0, 255)) + \
                                  ":%02x" % (random.randint(0, 255)) + \
                                  ":%02x" % (random.randint(0, 255))
                addr_map[addr] = anonymized_addr

    return anonymized_addr

def anonymize_ssid(ssid):

    global ssid_map
    global ssid_num

    anonymized_ssid = ssid

    if ssid:
        anonymized_ssid = ssid_map.get(ssid)
        if not anonymized_ssid:
            ssid_num += 1
            anonymized_ssid = "SSID_" + str(ssid_num)
            ssid_map[ssid] = anonymized_ssid

    return anonymized_ssid

def anonymize_dev_name(dev_name):

    global dev_name_map
    global dev_name_num

    anonymized_dev_name = dev_name

    if dev_name:
        anonymized_dev_name = dev_name_map.get(dev_name)
        if not anonymized_dev_name:
            dev_name_num += 1
            anonymized_dev_name = "Device_" + str(dev_name_num)
            dev_name_map[dev_name] = anonymized_dev_name

    return anonymized_dev_name

def zero_pad_buffer(buf, buflen):
    if len(buf) < buflen:
        for x in range(0, buflen - len(buf)):
            buf = buf + str(chr(0))
    return buf


if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: dot11anonymizer.py <input_file>")
        sys.exit(-1)

    input_file = sys.argv[1]
    output_file = os.path.splitext(input_file)[0] + '-anonymized.pcap'

    with PcapReader(input_file) as pcap_reader:

        pcap_writer = PcapWriter(output_file, sync=True)

        for pkt in pcap_reader:

            if pkt.haslayer(Dot11):

                # Determine if the FCS is good or bad (we'll use the information later),
                # but even if the FCS is bad, we will anonymize the frame
                raw = str(pkt.payload)
                fcs = raw[-4:]
                crc = struct.pack("I", zlib.crc32(raw[:-4]) & 0xffffffff)
                good_fcs = fcs == crc

                # Anonymize address fields
                pkt.addr1 = anonymize_address(pkt[Dot11].addr1)
                pkt.addr2 = anonymize_address(pkt[Dot11].addr2)
                pkt.addr3 = anonymize_address(pkt[Dot11].addr3)
                pkt.addr4 = anonymize_address(pkt[Dot11].addr4)

                # Anonymize SSID, device names (if present) and other address fields
                ie = pkt
                while Dot11Elt in ie:

                    ie = ie[Dot11Elt]
                    # SSID IE
                    if ie.ID == 0:
                        ssid = anonymize_ssid(ie.info)
                        ie.len = len(ssid)
                        ie.info = ssid

                    # Interworking (Hotspot 2.0) IE
                    elif ie.ID == 107:
                        hessid = ie.info[3:10] # HESSID
                        if hessid:
                            hessid = ':'.join(format(ord(c), '02x') for c in hessid)
                            hessid = mac2str(anonymize_address(hessid))
                            ie.info = ie.info[:3] + hessid + ie.info[10:]

                    # Cisco CCX1 CKIP ID IE (AP Name)
                    elif ie.ID == 133:
                        if ie.len >= 26:
                            ap_name = zero_pad_buffer(anonymize_dev_name(ie.info[10:26]), 16)
                            ie.info = ie.info[:10] + ap_name + ie.info[26:]

                    # Vendor Specific IE
                    elif ie.ID == 221:
                        ouitype = ie.info[:4]

                        # Aruba (AP Name)
                        if ouitype == '\x00\x0b\x86\x01':
                            if ord(ie.info[4]) == 3: # AP Name
                                ap_name = anonymize_dev_name(ie.info[6:])
                                ie.info = ie.info[:6] + ap_name
                                ie.len = 6 + len(ap_name)

                        # Zebra (AP Name)
                        if ouitype == '\x00\xa0\xf8\x01':
                            if ord(ie.info[4]) == 3:  # AP Name
                                ap_name = anonymize_dev_name(ie.info[12:])
                                ie.info = ie.info[:12] + ap_name
                                ie.len = 12 + len(ap_name)

                        # Aerohive (AP Name)
                        if ouitype == '\x00\x19\x77\x21':
			    if ord(ie.info[4]) == 1: # AP Name
                                ap_name = anonymize_dev_name(ie.info[7:]) + '\x00'
                                ie.info = ie.info[:6] + chr(len(ap_name)) + ap_name
                                ie.len = 7 + len(ap_name)

                        # Wi-Fi Alliance P2P IE
                        elif ouitype == '\x50\x6f\x9a\x09':
                            offset = 4
                            while offset + 3 < len(ie.info):
                                attr_type = ord(ie.info[offset])
                                attr_len  = ord(ie.info[offset+1]) + (ord(ie.info[offset+2]) << 8)
                                offset += 3

                                if attr_type == 3: # P2P Device ID
                                    device_id = ie.info[offset:offset+attr_len]
                                    device_id = ':'.join(format(ord(c), '02x') for c in device_id)
                                    device_id = mac2str(anonymize_address(device_id))
                                    ie.info = ie.info[:offset] + device_id + ie.info[offset+attr_len:]

                                offset += attr_len

                        # Microsoft WPS
                        elif ouitype == '\x00\x50\xf2\x04':
                            offset = 4
                            while offset + 4 < len(ie.info):

                                de_type = (ord(ie.info[offset]) << 8)   + ord(ie.info[offset+1])
                                de_len  = (ord(ie.info[offset+2]) << 8) + ord(ie.info[offset+3])
                                offset += 4

                                if de_type == 0x1011: # Device Name
                                    dev_name = ie.info[offset:offset+de_len]
                                    dev_name = anonymize_dev_name(dev_name)
                                    # Update data element length
                                    ie.info = ie.info[:offset-2] + struct.pack(">H", len(dev_name)) + ie.info[offset:]
                                    # Update data element value
                                    ie.info = ie.info[:offset] + dev_name + ie.info[offset+de_len:]
                                    # Update IE length
                                    ie.len  = len(ie.info)

                                offset += de_len

                    ie = ie.payload

                # Recompute FCS
                if good_fcs:
                    # If the FCS was originally good, then we recompute it
                    fcs = struct.pack("I", zlib.crc32(str(pkt.payload)[:-4]) & 0xffffffff)
                else:
                    # If the FCS was originally bad, we set it to 0x00000000
                    # to make sure it remains bad after the modifications to the frame
                    fcs = b'\x00\x00\x00\x00'

                # Write anonymized packet
                pcap_writer.write(RadioTap(str(pkt)[:-4] + str(fcs)))
