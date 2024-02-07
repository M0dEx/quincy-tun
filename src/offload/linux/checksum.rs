use std::net::IpAddr;

#[inline]
fn ip_addr_checksum(addr: IpAddr) -> u64 {
    match addr {
        IpAddr::V4(addr) => addr.octets().into_iter().map(|byte| byte as u64).sum(),
        IpAddr::V6(addr) => addr.octets().into_iter().map(|byte| byte as u64).sum(),
    }
}

#[inline]
pub(super) fn partial_header_checksum(
    protocol: u8,
    src_addr: IpAddr,
    dst_addr: IpAddr,
    packet_data_len: u16,
) -> u64 {
    let mut sum = protocol as u64;
    sum += ip_addr_checksum(src_addr);
    sum += ip_addr_checksum(dst_addr);
    sum += packet_data_len as u64;

    sum
}

#[inline]
pub(super) fn checksum(bytes: &[u8], initial: u64) -> u16 {
    let mut sum = initial;
    let mut chunks = bytes.chunks_exact(4);
    sum += chunks
        .by_ref()
        .map(|bytes| u32::from_be_bytes(bytes.try_into().expect("chunk is 4 bytes")) as u64)
        .sum::<u64>();

    // TODO: Do this in a more efficient way
    sum += match chunks.remainder().len() {
        1 => bytes[0] as u64,
        2 => u16::from_be_bytes(
            chunks
                .remainder()
                .try_into()
                .expect("chunk remainder is 2 bytes"),
        ) as u64,
        3 => {
            bytes[0] as u64
                + u16::from_be_bytes(
                    chunks.remainder()[1..]
                        .try_into()
                        .expect("chunk remainder is 2 bytes"),
                ) as u64
        }
        _ => unreachable!(),
    };

    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    sum as u16
}

#[inline]
pub(super) fn checksum_valid(
    src_addr: IpAddr,
    dst_addr: IpAddr,
    protocol: u8,
    ip_packet_data: &[u8],
) -> bool {
    let partial_checksum =
        partial_header_checksum(protocol, src_addr, dst_addr, ip_packet_data.len() as u16);

    checksum(ip_packet_data, partial_checksum) == 0xffff
}
