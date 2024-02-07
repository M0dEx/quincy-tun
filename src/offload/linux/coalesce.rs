//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use crate::offload::linux::tcp::TcpGroItem;
use crate::offload::linux::udp::UdpGroItem;
use crate::{Error, Result};
use bytes::{Bytes, BytesMut};
use etherparse::ip_number::{TCP, UDP};
use etherparse::{IpHeaders, Ipv4Header, Ipv6Header};

use super::checksum::checksum_valid;
use super::packet::{IpPacket, TcpPacket, UdpPacket};
use super::IpAddress;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Coalesce {
    Unavailable,
    Append,
    Prepend,
}

pub(crate) trait CoalesceIp {
    fn can_coalesce(&self, other: &Self) -> bool;
}

pub(crate) trait CoalesceTransport {
    type GroItem;

    fn can_coalesce(&self, packets: &Vec<BytesMut>, gro_item: &Self::GroItem) -> Coalesce;
    fn coalesce(
        &mut self,
        packets: &mut Vec<BytesMut>,
        gro_item: &mut Self::GroItem,
        coalesce: Coalesce,
    ) -> Result<()>;
}

impl CoalesceIp for Ipv4Header {
    #[inline]
    fn can_coalesce(&self, other: &Self) -> bool {
        if self.dscp != other.dscp {
            return false;
        }

        if self.ecn != other.ecn {
            return false;
        }

        if self.dont_fragment != other.dont_fragment {
            return false;
        }

        if self.time_to_live != other.time_to_live {
            return false;
        }

        true
    }
}

impl CoalesceIp for Ipv6Header {
    #[inline]
    fn can_coalesce(&self, other: &Self) -> bool {
        if self.traffic_class != other.traffic_class {
            return false;
        }

        if self.hop_limit != other.hop_limit {
            return false;
        }

        true
    }
}

impl CoalesceIp for IpHeaders {
    #[inline]
    fn can_coalesce(&self, other: &Self) -> bool {
        match (self, other) {
            (IpHeaders::Ipv4(self_ipv4_header, _), IpHeaders::Ipv4(other_ipv4_header, _)) => {
                self_ipv4_header.can_coalesce(other_ipv4_header)
            }
            (IpHeaders::Ipv6(self_ipv6_header, _), IpHeaders::Ipv6(other_ipv6_header, _)) => {
                self_ipv6_header.can_coalesce(other_ipv6_header)
            }
            _ => false,
        }
    }
}

impl CoalesceTransport for TcpPacket {
    type GroItem = TcpGroItem;

    #[inline]
    fn can_coalesce(&self, packets: &Vec<BytesMut>, gro_item: &TcpGroItem) -> Coalesce {
        if !self.ip_header.can_coalesce(&gro_item.ip_header) {
            return Coalesce::Unavailable;
        }

        let tcp_header = &self.transport_header;
        let item_tcp_header = &gro_item.tcp_header;
        let target_data = &packets[gro_item.packet_idx]
            [gro_item.ip_header.header_len() + gro_item.tcp_header.header_len()..];
        let data = &self.data[self.ip_header.header_len() + self.transport_header.header_len()..];

        if tcp_header.options != item_tcp_header.options {
            return Coalesce::Unavailable;
        }

        let mut stream_len = gro_item.size + gro_item.num_merged * gro_item.size;

        if tcp_header.psh {
            return Coalesce::Unavailable;
        }

        // self follows the item from a sequence number perspective.
        if tcp_header.sequence_number == gro_item.seq_num + stream_len {
            if target_data.len() % gro_item.size as usize != 0 {
                return Coalesce::Unavailable;
            }

            if data.len() > target_data.len() {
                return Coalesce::Unavailable;
            }

            return Coalesce::Append;
        } else if tcp_header.sequence_number + data.len() as u32 == gro_item.seq_num {
            if data.len() < gro_item.size as usize {
                return Coalesce::Unavailable;
            }

            if data.len() > gro_item.size as usize && gro_item.num_merged > 0 {
                return Coalesce::Unavailable;
            }

            return Coalesce::Prepend;
        }

        Coalesce::Unavailable
    }

    #[inline]
    fn coalesce(
        &mut self,
        packets: &mut Vec<BytesMut>,
        gro_item: &mut Self::GroItem,
        coalesce: Coalesce,
    ) -> Result<()> {
        let packet_head: &[u8];
        let header_len = gro_item.ip_header.header_len() + gro_item.tcp_header.header_len();
        let target_packet = &mut packets[gro_item.packet_idx];
        let coalesced_len = target_packet.len() + self.data.len() - header_len;

        match coalesce {
            Coalesce::Prepend => {
                packet_head = &self.data;

                if gro_item.num_merged == 0 {
                    let item_checksum_valid = checksum_valid(
                        gro_item.ip_header.src_addr(),
                        gro_item.ip_header.dst_addr(),
                        TCP.0,
                        &target_packet[gro_item.ip_header.header_len()..],
                    );

                    if !item_checksum_valid {
                        return Err(Error::OffloadItemInvalidChecksum);
                    }
                }

                let self_checksum_valid = checksum_valid(
                    self.ip_header.src_addr(),
                    self.ip_header.dst_addr(),
                    TCP.0,
                    &self.data,
                );

                if !self_checksum_valid {
                    return Err(Error::OffloadPacketInvalidChecksum);
                }

                gro_item.seq_num = self.transport_header.sequence_number;
                let extend_bytes = coalesced_len - packet_head.len();
                packets[]
            }
            Coalesce::Append => {}
            Coalesce::Unavailable => {
                unreachable!()
            }
        }

        Ok(())
    }
}

impl CoalesceTransport for IpPacket<UdpPacket> {
    type GroItem = UdpGroItem;

    #[inline]
    fn can_coalesce(&self, packets: &Vec<BytesMut>, gro_item: &UdpGroItem) -> Coalesce {
        if !self.ip_header.can_coalesce(&gro_item.ip_header) {
            return Coalesce::Unavailable;
        }

        let target_data = &packets[gro_item.packet_idx]
            [gro_item.ip_header.header_len() + gro_item.udp_header.header_len()..];

        if target_data.len() % gro_item.size as usize != 0 {
            return Coalesce::Unavailable;
        }

        if self.transport_header.data.len() > gro_item.size as usize {
            return Coalesce::Unavailable;
        }

        Coalesce::Append
    }

    #[inline]
    fn coalesce(&mut self, gro_item: &mut UdpGroItem) -> Result<()> {
        let src_addr = self.src_addr();
        let dst_addr = self.dst_addr();
        let item_src_addr = gro_item.packet.src_addr();
        let item_dst_addr = gro_item.packet.dst_addr();
        let data = &self.transport_header.data;
        let item_data = &mut gro_item.packet.transport.data;

        if item_data.remaining_mut() < data.len() {
            return Err(Error::BufferTooSmall);
        }

        if gro_item.num_merged == 0 {
            let item_checksum_invalid = gro_item.checksum_known_invalid
                || !checksum_valid(item_src_addr, item_dst_addr, UDP.0, item_data);

            if item_checksum_invalid {
                return Err(Error::OffloadItemInvalidChecksum);
            }
        }

        let checksum_valid = checksum_valid(src_addr, dst_addr, UDP.0, data);

        if !checksum_valid {
            return Err(Error::OffloadPacketInvalidChecksum);
        }

        item_data.chunk_mut().copy_from_slice(data);
        gro_item.num_merged += 1;

        Ok(())
    }
}
