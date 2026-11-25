// SPDX-License-Identifier: GPL-2.0-only
// Copyright (C) 2026 John Crispin <john@phrozen.org>

//! Crafted frame injection over AF_PACKET, run inside a port's namespace.
//!
//! Frames are built byte by byte rather than through a packet library, which is
//! the point: a deliberately wrong checksum has to survive to the wire, and the
//! caller must turn tx_checksum off first or the NIC recomputes a correct one.

use serde::Deserialize;
use serde_json::json;

use super::{emit, spec_read};

pub const BAD_CHECKSUM: u16 = 0xDEAD;
const ETH_HEADER: usize = 14;
const IPV4_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;
const UDP_HEADER: usize = 8;
const TCP_HEADER: usize = 20;
/// The MAC pads anything shorter, so a true runt cannot be emitted at all.
const MIN_FRAME: usize = 60;

#[derive(Debug, Deserialize)]
pub struct InjectSpec {
    pub iface: String,
    pub kind: String,
    #[serde(default = "one")]
    pub count: u32,
    #[serde(default)]
    pub ethertype: Option<u16>,
    #[serde(default)]
    pub src_ip: Option<String>,
    #[serde(default)]
    pub dst_ip: Option<String>,
    #[serde(default = "sport")]
    pub sport: u16,
    #[serde(default = "dport")]
    pub dport: u16,
    #[serde(default = "four")]
    pub version: u8,
    #[serde(default = "syn")]
    pub flags: String,
    #[serde(default)]
    pub payload: Option<String>,
    #[serde(default)]
    pub src_mac: Option<String>,
    #[serde(default)]
    pub dst_mac: Option<String>,
    #[serde(default)]
    pub bad_checksum: bool,
    #[serde(default)]
    pub zero_checksum: bool,
    #[serde(default)]
    pub fragment_size: Option<usize>,
}

fn one() -> u32 {
    1
}
fn sport() -> u16 {
    12345
}
fn dport() -> u16 {
    9999
}
fn four() -> u8 {
    4
}
fn syn() -> String {
    "S".into()
}

pub fn mac_parse(mac: &str) -> Option<[u8; 6]> {
    let parts: Vec<u8> = mac
        .split(':')
        .filter_map(|p| u8::from_str_radix(p, 16).ok())
        .collect();
    (parts.len() == 6).then(|| parts.try_into().expect("checked length"))
}

/// Internet checksum over a byte run, RFC 1071.
pub fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = bytes.chunks_exact(2);
    for pair in &mut chunks {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    if let [odd] = chunks.remainder() {
        sum += (*odd as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Checksum over the IPv4 or IPv6 pseudo-header plus the layer-4 segment.
pub fn l4_checksum(src: &[u8], dst: &[u8], protocol: u8, segment: &[u8]) -> u16 {
    let mut buffer = Vec::with_capacity(src.len() + dst.len() + 8 + segment.len());
    buffer.extend_from_slice(src);
    buffer.extend_from_slice(dst);
    if src.len() == 4 {
        buffer.push(0);
        buffer.push(protocol);
        buffer.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    } else {
        buffer.extend_from_slice(&(segment.len() as u32).to_be_bytes());
        buffer.extend_from_slice(&[0, 0, 0, protocol]);
    }
    buffer.extend_from_slice(segment);
    let sum = checksum(&buffer);
    // A zero checksum means "not computed" for UDP, so the ones-complement
    // alternative is sent instead.
    if sum == 0 && protocol == 17 {
        0xFFFF
    } else {
        sum
    }
}

fn tcp_flag_bits(flags: &str) -> u8 {
    flags.chars().fold(0u8, |bits, flag| {
        bits | match flag.to_ascii_uppercase() {
            'F' => 0x01,
            'S' => 0x02,
            'R' => 0x04,
            'P' => 0x08,
            'A' => 0x10,
            'U' => 0x20,
            _ => 0,
        }
    })
}

pub fn ipv4_header(src: [u8; 4], dst: [u8; 4], protocol: u8, payload_len: usize, offset: usize, more: bool) -> Vec<u8> {
    let mut header = Vec::with_capacity(IPV4_HEADER);
    header.extend_from_slice(&[0x45, 0x00]);
    header.extend_from_slice(&((IPV4_HEADER + payload_len) as u16).to_be_bytes());
    header.extend_from_slice(&1u16.to_be_bytes());
    let fragment = ((offset / 8) as u16) | if more { 0x2000 } else { 0 };
    header.extend_from_slice(&fragment.to_be_bytes());
    header.extend_from_slice(&[64, protocol, 0, 0]);
    header.extend_from_slice(&src);
    header.extend_from_slice(&dst);
    let sum = checksum(&header);
    header[10..12].copy_from_slice(&sum.to_be_bytes());
    header
}

pub fn ipv6_header(src: [u8; 16], dst: [u8; 16], next: u8, payload_len: usize) -> Vec<u8> {
    let mut header = Vec::with_capacity(IPV6_HEADER);
    header.extend_from_slice(&[0x60, 0, 0, 0]);
    header.extend_from_slice(&(payload_len as u16).to_be_bytes());
    header.push(next);
    header.push(64);
    header.extend_from_slice(&src);
    header.extend_from_slice(&dst);
    header
}

pub fn udp_segment(spec: &InjectSpec, src: &[u8], dst: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(UDP_HEADER + payload.len());
    segment.extend_from_slice(&spec.sport.to_be_bytes());
    segment.extend_from_slice(&spec.dport.to_be_bytes());
    segment.extend_from_slice(&((UDP_HEADER + payload.len()) as u16).to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);

    let sum = if spec.zero_checksum {
        0
    } else if spec.bad_checksum {
        BAD_CHECKSUM
    } else {
        l4_checksum(src, dst, 17, &segment)
    };
    segment[6..8].copy_from_slice(&sum.to_be_bytes());
    segment
}

pub fn tcp_segment(spec: &InjectSpec, src: &[u8], dst: &[u8], payload: &[u8]) -> Vec<u8> {
    let mut segment = Vec::with_capacity(TCP_HEADER + payload.len());
    segment.extend_from_slice(&spec.sport.to_be_bytes());
    segment.extend_from_slice(&spec.dport.to_be_bytes());
    segment.extend_from_slice(&0u32.to_be_bytes());
    segment.extend_from_slice(&0u32.to_be_bytes());
    segment.push(0x50);
    segment.push(tcp_flag_bits(&spec.flags));
    segment.extend_from_slice(&8192u16.to_be_bytes());
    segment.extend_from_slice(&[0, 0, 0, 0]);
    segment.extend_from_slice(payload);

    let sum = if spec.bad_checksum {
        BAD_CHECKSUM
    } else {
        l4_checksum(src, dst, 6, &segment)
    };
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    segment
}

fn ethernet(dst_mac: [u8; 6], src_mac: [u8; 6], ethertype: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(ETH_HEADER);
    header.extend_from_slice(&dst_mac);
    header.extend_from_slice(&src_mac);
    header.extend_from_slice(&ethertype.to_be_bytes());
    header
}

/// Build every frame the spec asks for, already padded to the Ethernet minimum.
pub fn frames_build(spec: &InjectSpec, local_mac: [u8; 6], peer_mac: [u8; 6]) -> Result<Vec<Vec<u8>>, String> {
    let src_mac = spec.src_mac.as_deref().and_then(mac_parse).unwrap_or(local_mac);
    let dst_mac = spec.dst_mac.as_deref().and_then(mac_parse).unwrap_or(peer_mac);
    let payload = spec
        .payload
        .clone()
        .unwrap_or_else(|| "tgen".to_string())
        .into_bytes();

    let frames = match spec.kind.as_str() {
        "ether" => {
            let ethertype = spec
                .ethertype
                .ok_or("kind 'ether' needs an ethertype, for example 34997 (0x88b5)")?;
            let mut frame = ethernet(dst_mac, src_mac, ethertype);
            frame.extend_from_slice(&payload);
            vec![frame]
        }
        "udp" | "tcp" => {
            let (src_ip, dst_ip) = (
                spec.src_ip.as_deref().ok_or("needs src_ip")?,
                spec.dst_ip.as_deref().ok_or("needs dst_ip")?,
            );
            if spec.version == 6 {
                if spec.fragment_size.is_some() {
                    return Err("fragment_size is only wired for ipv4".into());
                }
                let src: [u8; 16] = src_ip
                    .parse::<std::net::Ipv6Addr>()
                    .map_err(|e| format!("src_ip: {e}"))?
                    .octets();
                let dst: [u8; 16] = dst_ip
                    .parse::<std::net::Ipv6Addr>()
                    .map_err(|e| format!("dst_ip: {e}"))?
                    .octets();
                let protocol = if spec.kind == "udp" { 17 } else { 6 };
                let segment = if spec.kind == "udp" {
                    udp_segment(spec, &src, &dst, &payload)
                } else {
                    tcp_segment(spec, &src, &dst, &payload)
                };
                let mut frame = ethernet(dst_mac, src_mac, 0x86DD);
                frame.extend_from_slice(&ipv6_header(src, dst, protocol, segment.len()));
                frame.extend_from_slice(&segment);
                vec![frame]
            } else {
                let src: [u8; 4] = src_ip
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|e| format!("src_ip: {e}"))?
                    .octets();
                let dst: [u8; 4] = dst_ip
                    .parse::<std::net::Ipv4Addr>()
                    .map_err(|e| format!("dst_ip: {e}"))?
                    .octets();
                let protocol = if spec.kind == "udp" { 17 } else { 6 };
                let segment = if spec.kind == "udp" {
                    udp_segment(spec, &src, &dst, &payload)
                } else {
                    tcp_segment(spec, &src, &dst, &payload)
                };
                fragments_build(spec, src, dst, protocol, &segment, dst_mac, src_mac)?
            }
        }
        other => return Err(format!("unknown kind {other:?}; accepted: ether, udp, tcp")),
    };

    Ok(frames
        .into_iter()
        .map(|mut frame| {
            if frame.len() < MIN_FRAME {
                frame.resize(MIN_FRAME, 0);
            }
            frame
        })
        .collect())
}

fn fragments_build(
    spec: &InjectSpec,
    src: [u8; 4],
    dst: [u8; 4],
    protocol: u8,
    segment: &[u8],
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
) -> Result<Vec<Vec<u8>>, String> {
    let Some(size) = spec.fragment_size else {
        let mut frame = ethernet(dst_mac, src_mac, 0x0800);
        frame.extend_from_slice(&ipv4_header(src, dst, protocol, segment.len(), 0, false));
        frame.extend_from_slice(segment);
        return Ok(vec![frame]);
    };
    if size == 0 || size % 8 != 0 {
        return Err("fragment_size must be a non-zero multiple of 8".into());
    }

    let mut frames = Vec::new();
    let mut offset = 0;
    while offset < segment.len() {
        let end = (offset + size).min(segment.len());
        let more = end < segment.len();
        let mut frame = ethernet(dst_mac, src_mac, 0x0800);
        frame.extend_from_slice(&ipv4_header(src, dst, protocol, end - offset, offset, more));
        frame.extend_from_slice(&segment[offset..end]);
        frames.push(frame);
        offset = end;
    }
    Ok(frames)
}

fn iface_index(name: &str) -> Option<u32> {
    let cstr = std::ffi::CString::new(name).ok()?;
    let index = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
    (index != 0).then_some(index)
}

fn iface_mac(name: &str) -> Option<[u8; 6]> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{name}/address")).ok()?;
    mac_parse(text.trim())
}

pub fn run() -> anyhow::Result<()> {
    let spec: InjectSpec = spec_read()?;
    let local_mac = iface_mac(&spec.iface).unwrap_or([0; 6]);
    let frames = match frames_build(&spec, local_mac, [0xFF; 6]) {
        Ok(frames) => frames,
        Err(message) => {
            emit(&json!({"error": message}));
            return Ok(());
        }
    };
    let Some(index) = iface_index(&spec.iface) else {
        emit(&json!({"error": format!("no such interface: {}", spec.iface)}));
        return Ok(());
    };

    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_RAW, 0) };
    if fd < 0 {
        emit(&json!({"error": "cannot open an AF_PACKET socket (needs root)"}));
        return Ok(());
    }

    let mut address: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
    address.sll_family = libc::AF_PACKET as u16;
    address.sll_ifindex = index as i32;
    address.sll_halen = 6;

    let mut sent = 0u64;
    for _ in 0..spec.count {
        for frame in &frames {
            address.sll_addr[..6].copy_from_slice(&frame[0..6]);
            let written = unsafe {
                libc::sendto(
                    fd,
                    frame.as_ptr() as *const libc::c_void,
                    frame.len(),
                    0,
                    &address as *const _ as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t,
                )
            };
            if written > 0 {
                sent += 1;
            }
        }
    }
    unsafe {
        libc::close(fd);
    }

    emit(&json!({
        "sent": sent,
        "frames_per_round": frames.len(),
        "rounds": spec.count,
        "bytes_each": frames.iter().map(|f| f.len()).collect::<Vec<_>>(),
    }));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: &str) -> InjectSpec {
        InjectSpec {
            iface: "eth0".into(),
            kind: kind.into(),
            count: 1,
            ethertype: Some(0x88B5),
            src_ip: Some("10.80.0.1".into()),
            dst_ip: Some("10.80.0.2".into()),
            sport: 12345,
            dport: 9999,
            version: 4,
            flags: "S".into(),
            payload: Some("tgen".into()),
            src_mac: None,
            dst_mac: None,
            bad_checksum: false,
            zero_checksum: false,
            fragment_size: None,
        }
    }

    const LOCAL: [u8; 6] = [0x3c, 0xfd, 0xfe, 0x97, 0x8e, 0x98];
    const PEER: [u8; 6] = [0x3c, 0xfd, 0xfe, 0x97, 0x8e, 0x99];

    #[test]
    fn checksum_matches_a_known_vector() {
        // RFC 1071 worked example.
        assert_eq!(checksum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]), 0x220d);
    }

    #[test]
    fn checksum_handles_an_odd_length() {
        assert_eq!(checksum(&[0x01]), checksum(&[0x01, 0x00]));
    }

    #[test]
    fn ipv4_header_checksum_verifies_to_zero() {
        let header = ipv4_header([10, 80, 0, 1], [10, 80, 0, 2], 17, 12, 0, false);
        assert_eq!(header.len(), IPV4_HEADER);
        // A correct header checksums to zero over the whole header.
        assert_eq!(checksum(&header), 0);
    }

    #[test]
    fn ethernet_and_ip_headers_are_where_tcpdump_expects() {
        let frames = frames_build(&spec("udp"), LOCAL, PEER).unwrap();
        let frame = &frames[0];
        assert_eq!(&frame[0..6], &PEER, "destination mac first");
        assert_eq!(&frame[6..12], &LOCAL, "then source mac");
        assert_eq!(&frame[12..14], &[0x08, 0x00], "then the ipv4 ethertype");
        assert_eq!(frame[14], 0x45, "version 4, 5-word header");
        assert_eq!(frame[23], 17, "udp protocol number");
    }

    #[test]
    fn bad_checksum_survives_into_the_segment() {
        let mut wanted = spec("udp");
        wanted.bad_checksum = true;
        let frame = &frames_build(&wanted, LOCAL, PEER).unwrap()[0];
        let offset = ETH_HEADER + IPV4_HEADER + 6;
        assert_eq!(
            u16::from_be_bytes([frame[offset], frame[offset + 1]]),
            BAD_CHECKSUM
        );
    }

    #[test]
    fn zero_checksum_is_written_as_zero_not_recomputed() {
        let mut wanted = spec("udp");
        wanted.zero_checksum = true;
        let frame = &frames_build(&wanted, LOCAL, PEER).unwrap()[0];
        let offset = ETH_HEADER + IPV4_HEADER + 6;
        assert_eq!(u16::from_be_bytes([frame[offset], frame[offset + 1]]), 0);
    }

    #[test]
    fn a_correct_udp_checksum_is_never_zero_on_the_wire() {
        // 0 means "not computed" for UDP, so the alternative encoding is used.
        let sum = l4_checksum(&[0, 0, 0, 0], &[0, 0, 0, 0], 17, &[0, 0, 0, 0, 0, 0, 0, 0]);
        assert_ne!(sum, 0);
    }

    #[test]
    fn tcp_flags_map_to_bits() {
        assert_eq!(tcp_flag_bits("S"), 0x02);
        assert_eq!(tcp_flag_bits("SA"), 0x12);
        assert_eq!(tcp_flag_bits("FPA"), 0x19);
        assert_eq!(tcp_flag_bits(""), 0);
    }

    #[test]
    fn fragments_carry_rising_offsets_and_the_more_flag() {
        let mut wanted = spec("udp");
        wanted.payload = Some("X".repeat(600));
        wanted.fragment_size = Some(200);
        let frames = frames_build(&wanted, LOCAL, PEER).unwrap();
        assert_eq!(frames.len(), 4, "608 bytes of segment in 200-byte fragments");

        let fragment_field = |frame: &Vec<u8>| {
            u16::from_be_bytes([frame[ETH_HEADER + 6], frame[ETH_HEADER + 7]])
        };
        assert_eq!(fragment_field(&frames[0]) & 0x1FFF, 0);
        assert_eq!(fragment_field(&frames[1]) & 0x1FFF, 200 / 8);
        assert_eq!(fragment_field(&frames[2]) & 0x1FFF, 400 / 8);
        assert_eq!(fragment_field(&frames[0]) & 0x2000, 0x2000, "more fragments");
        assert_eq!(fragment_field(&frames[3]) & 0x2000, 0, "last has it clear");
    }

    #[test]
    fn fragment_size_must_be_a_multiple_of_eight() {
        let mut wanted = spec("udp");
        wanted.fragment_size = Some(100);
        assert!(frames_build(&wanted, LOCAL, PEER)
            .unwrap_err()
            .contains("multiple of 8"));
    }

    #[test]
    fn ipv6_frames_use_the_right_ethertype_and_header() {
        let mut wanted = spec("udp");
        wanted.version = 6;
        wanted.src_ip = Some("fd00:80::1".into());
        wanted.dst_ip = Some("fd00:80::2".into());
        let frame = &frames_build(&wanted, LOCAL, PEER).unwrap()[0];
        assert_eq!(&frame[12..14], &[0x86, 0xDD]);
        assert_eq!(frame[14] >> 4, 6, "version nibble");
        assert_eq!(frame[20], 17, "next header is udp");
    }

    #[test]
    fn ipv6_fragmentation_is_refused_rather_than_silently_wrong() {
        let mut wanted = spec("udp");
        wanted.version = 6;
        wanted.src_ip = Some("fd00::1".into());
        wanted.dst_ip = Some("fd00::2".into());
        wanted.fragment_size = Some(200);
        assert!(frames_build(&wanted, LOCAL, PEER).unwrap_err().contains("only wired for ipv4"));
    }

    #[test]
    fn a_spoofed_source_mac_reaches_the_frame() {
        let mut wanted = spec("udp");
        wanted.src_mac = Some("02:de:ad:be:ef:01".into());
        let frame = &frames_build(&wanted, LOCAL, PEER).unwrap()[0];
        assert_eq!(&frame[6..12], &[0x02, 0xde, 0xad, 0xbe, 0xef, 0x01]);
    }

    #[test]
    fn frames_are_padded_to_the_ethernet_minimum() {
        // A true runt is impossible: the MAC pads anything shorter anyway.
        let mut wanted = spec("ether");
        wanted.payload = Some("x".into());
        let frame = &frames_build(&wanted, LOCAL, PEER).unwrap()[0];
        assert_eq!(frame.len(), MIN_FRAME);
    }

    #[test]
    fn unknown_kind_and_missing_fields_are_named() {
        assert!(frames_build(&spec("sctp"), LOCAL, PEER).unwrap_err().contains("unknown kind"));
        let mut wanted = spec("ether");
        wanted.ethertype = None;
        assert!(frames_build(&wanted, LOCAL, PEER).unwrap_err().contains("needs an ethertype"));
        let mut wanted = spec("udp");
        wanted.src_ip = None;
        assert!(frames_build(&wanted, LOCAL, PEER).unwrap_err().contains("needs src_ip"));
    }
}
