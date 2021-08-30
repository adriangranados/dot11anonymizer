#
# dot11anonymizer.py
# This script anonymizes 802.11 Layer 2 information found in capture files.
# Version 2.0
#
# Copyright (c) 2019-2021 Adrian Granados. All rights reserved.
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

def zero_pad_buffer(buf, buflen):
    if len(buf) < buflen:
        for x in range(0, buflen - len(buf)):
            buf = buf + b'\0'
    return buf

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
            anonymized_ssid = bytes("SSID_" + str(ssid_num), encoding='ascii')
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
            anonymized_dev_name = bytes("Device_" + str(dev_name_num), encoding='ascii')
            dev_name_map[dev_name] = anonymized_dev_name

    return anonymized_dev_name

def anonymize_ssid_ie(ie):
    ssid = anonymize_ssid(ie.info)
    ie.len = len(ssid)
    ie.info = ssid

def anonymize_multiple_bssid_ie(ie):
    offset = 1
    subelements = bytes()

    while offset < ie.len:
        subelementID  = ie.info[offset]
        subelementLen = ie.info[offset + 1]
        offset += 2

        subelementPayload = ie.info[offset:offset+subelementLen]

        if subelementID == 0: # Nontransmitted BSSID Profile
            subelementOffset  = 0
            subelementPayloadNew = bytes()
            while subelementOffset < subelementLen:
                tagID  = subelementPayload[subelementOffset]
                tagLen = subelementPayload[subelementOffset + 1]
                subelementOffset += 2;
                nontransmitted_ie = Dot11Elt(ID=tagID, len=tagLen, info=subelementPayload[subelementOffset:subelementOffset+tagLen])
                anonymized_ie = anonymize_ie(nontransmitted_ie)
                subelementPayloadNew += bytes([anonymized_ie.ID]) + bytes([anonymized_ie.len]) + anonymized_ie.info
                subelementOffset += tagLen

            subelementNew = bytes([subelementID]) + bytes([len(subelementPayloadNew)]) + subelementPayloadNew
        else:
            subelementNew = bytes([subelementID]) + bytes([subelementLen]) + subelementPayload

        subelements += subelementNew
        offset += subelementLen

    ie.info = bytes([ie.info[0]]) + subelements
    ie.len  = 1 + len(subelements)

def anonymize_interworking_ie(ie):
    hessid = ie.info[3:10] # HESSID
    if hessid:
        hessid = ':'.join(format(c, '02x') for c in hessid)
        hessid = mac2str(anonymize_address(hessid))
        ie.info = b''.join([ie.info[:3], hessid, ie.info[10:]])

def anonymize_cisco_ccx_id_ie(ie):
    if ie.len >= 26:
        ap_name = zero_pad_buffer(anonymize_dev_name(ie.info[10:26]), 16)
        ie.info = b''.join([ie.info[:10], ap_name, ie.info[26:]])

def anonymize_vendor_specific_ie(ie):
    ouitype = ie.info[:4]
    ie_info = ie.info
    ie_len  = ie.len

    # Aruba (AP Name)
    if ouitype == b'\x00\x0b\x86\x01':
        if ie_info[4] == 3: # AP Name
            ap_name = anonymize_dev_name(ie_info[6:])
            ie_info = b''.join([ie_info[:6], ap_name])
            ie_len  = 6 + len(ap_name)

    # Zebra (AP Name)
    if ouitype == b'\x00\xa0\xf8\x01':
        if ie_info[4] == 3:  # AP Name
            ap_name = anonymize_dev_name(ie_infoo[12:])
            ie_info = b''.join([ie_infoo[:12], ap_name])
            ie_len  = 12 + len(ap_name)

    # Aerohive (AP Name)
    if ouitype == b'\x00\x19\x77\x21':
        if ie.info[4] == 1: # Host Name
            ap_name = anonymize_dev_name(ie_info[7:]) + b'\0'
            ie_info = b''.join([ie_info[:6], bytes([len(ap_name)]), ap_name])
            ie_len  = 7 + len(ap_name)

    # MikroTik (AP Name)
    if ouitype == b'\x00\x0C\x42\x00':
        tlv_offset = 4

        while tlv_offset < ie.len:

            tlv_type = ord(ie_info[tlv_offset])
            tlv_offset += 1
            tlv_len = ord(ie_info[tlv_offset])
            tlv_offset += 1

            if tlv_type == 1: # Radio Name
                ap_name = zero_pad_buffer(anonymize_dev_name(ie_info[tlv_offset + 10:tlv_offset + tlv_len]), 20)
                ie_info = b''.join([ie_info[:tlv_offset + 10], ap_name, ie_info[tlv_offset + tlv_len:]])

            tlv_offset = tlv_offset + tlv_len

    # Mist (AP Name)
    if ouitype == b'\x5c\x5b\x35\x01':
        ap_name = anonymize_dev_name(ie_info[4:]) + b'\0'
        ie_info = b''.join([ie_info[:4], ap_name])
        ie_len  = 4 + len(ap_name)

    # Wi-Fi Alliance P2P IE
    elif ouitype == b'\x50\x6f\x9a\x09':
        offset = 4
        while offset + 3 < len(ie_info):
            attr_type = ie_info[offset]
            attr_len  = ie_info[offset+1] + (ie_info[offset+2] << 8)
            offset += 3

            if attr_type == 3: # P2P Device ID
                device_id = ie_info[offset:offset+attr_len]
                device_id = ':'.join(format(c, '02x') for c in device_id)
                device_id = mac2str(anonymize_address(device_id))
                ie_info = b''.join([ie_info[:offset], device_id, ie_info[offset+attr_len:]])
            offset += attr_len

    # Microsoft WPS
    elif ouitype == b'\x00\x50\xf2\x04':
        offset = 4
        while offset + 4 < len(ie_info):

            de_type = (ie_info[offset] << 8)   + ie_info[offset+1]
            de_len  = (ie_info[offset+2] << 8) + ie_info[offset+3]
            offset += 4

            if de_type == 0x1011: # Device Name
                dev_name = ie_info[offset:offset+de_len]
                dev_name = anonymize_dev_name(dev_name)
                # Update data element length
                ie_info = b''.join([ie_info[:offset-2], struct.pack(">H", len(dev_name)), ie_info[offset:]])
                # Update data element value
                ie_info = b''.join([ie_info[:offset], dev_name, ie_info[offset+de_len:]])
                # Update IE length
                ie_len  = len(ie_info)

            offset += de_len

    ie.info = ie_info[3:]
    ie.len  = ie_len

def anonymize_ie(ie):
    if ie.ID == 0: # SSID
        anonymize_ssid_ie(ie)
    elif ie.ID == 71: # Multiple BSSID
        anonymize_multiple_bssid_ie(ie)
    elif ie.ID == 107: # Interworking (Hotspot 2.0)
        anonymize_interworking_ie(ie)
    elif ie.ID == 133: # Cisco CCX1 CKIP ID (AP Name)
        anonymize_cisco_ccx_id_ie(ie)
    if ie.ID == 221: # Vendor Specific
        if ie.haslayer(Dot11EltVendorSpecific):
            anonymize_vendor_specific_ie(ie[Dot11EltVendorSpecific])

    return ie

def anonymize_file(input_file, output_file):

    with PcapReader(input_file) as pcap_reader:

        pcap_writer = PcapWriter(output_file, sync=True)

        for pkt in pcap_reader:

            if pkt.haslayer(RadioTap):

                if pkt.haslayer(Dot11):

                    # Check if frame has FCS
                    has_fcs = False
                    radiotap = pkt[RadioTap]
                    if radiotap.Flags & 0x10:
                        has_fcs = True

                        # Determine if the FCS is good or bad (we'll use the information later),
                        # but even if the FCS is bad, we will anonymize the frame
                        raw = bytes(pkt.payload)
                        fcs = raw[-4:]
                        crc = struct.pack("I", zlib.crc32(raw[:-4]) & 0xffffffff)
                        good_fcs = fcs == crc

                    # Anonymize address fields
                    pkt.addr1 = anonymize_address(pkt[Dot11].addr1)
                    pkt.addr2 = anonymize_address(pkt[Dot11].addr2)
                    pkt.addr3 = anonymize_address(pkt[Dot11].addr3)
                    pkt.addr4 = anonymize_address(pkt[Dot11].addr4)

                    # Anonymize information elements
                    if pkt.haslayer(Dot11Elt):
                        subpkt = pkt[Dot11Elt]
                        while Dot11Elt in subpkt:
                            ie = subpkt[Dot11Elt]
                            anonymize_ie(ie)
                            subpkt = subpkt.payload

                    # Recompute FCS
                    if has_fcs:
                        if good_fcs:
                            # If the FCS was originally good, then we recompute it
                            fcs = struct.pack("I", zlib.crc32(bytes(pkt[Dot11])[:-4]) & 0xffffffff)
                        else:
                            # If the FCS was originally bad, we set it to 0x00000000
                            # to make sure it remains bad after the modifications to the frame
                            fcs = b'\x00\x00\x00\x00'

                        # Write anonymized packet with new FCS
                        pcap_writer.write(RadioTap(bytes(pkt)[:-4] + fcs))
                    else:
                        # Write anonymized packet
                        pcap_writer.write(RadioTap(bytes(pkt)))

if __name__ == "__main__":

    if len(sys.argv) < 2:
        print("Usage: dot11anonymizer.py <input_file> [<input_file> ...]")
        sys.exit(-1)

    for input_file in sys.argv[1:]:
        output_file = os.path.splitext(input_file)[0] + '-anonymized.pcap'
        anonymize_file(input_file, output_file)
