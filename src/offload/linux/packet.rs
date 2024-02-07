use bytes::Bytes;
use etherparse::{IpHeaders, TcpHeader, UdpHeader};

#[derive(Clone, Debug)]
pub(crate) struct IpPacket<Transport> {
    pub(crate) ip_header: IpHeaders,
    pub(crate) transport_header: Transport,
    pub(crate) data: Bytes,
}

pub(crate) type TcpPacket = IpPacket<TcpHeader>;
pub(crate) type UdpPacket = IpPacket<UdpHeader>;
