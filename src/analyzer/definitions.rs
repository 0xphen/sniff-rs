use pcap::PacketHeader;

pub enum ReadPacketResult {
    Success((PacketHeader, Vec<u8>)),
    Error(String),
}
