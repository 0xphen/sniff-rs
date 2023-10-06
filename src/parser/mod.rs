pub mod ipv4;

/// Represents a protocol parser responsible for interpreting packet data.
///
/// The `ProtocolParser` trait provides a standardized interface for both
/// parsing raw packet data and serializing structured packet representations
/// back into their raw byte form.
///
/// Implementors of this trait can be used to support various network
/// protocols or custom packet formats.
///
/// # Examples
///
/// ```
/// struct MyProtocolParser;
///
/// impl ProtocolParser for MyProtocolParser {
///     fn parse(&self, data: &[u8]) -> ParsedPacket {
///         // Parse the data according to MyProtocol's rules
///         // ...
///     }
///
///     fn serialize(&self, packet: &ParsedPacket) -> Vec<u8> {
///         // Convert the ParsedPacket back into raw byte format
///         // ...
///     }
/// }
/// `
pub trait ProtocolParser {
    /// Parses raw packet data into a structured representation.
    ///
    /// The returned `ParsedPacket` should provide an accessible representation
    /// of the packet's contents, according to the specifics of the protocol.
    ///
    /// # Parameters
    ///
    /// - `data`: A byte slice containing the raw packet data to be parsed.
    ///
    /// # Returns
    ///
    /// - A `ParsedPacket` representing the structured data.
  fn parse(&self, data: [u8]) -> ParsedPacket;

      /// Serializes a structured packet representation back into raw byte form.
    ///
    /// This method is used to prepare packets for transmission over the
    /// network or storage in byte-based formats.
    ///
    /// # Parameters
    ///
    /// - `packet`: A reference to the structured `ParsedPacket` that needs
    ///   to be serialized.
    ///
    /// # Returns
    ///
    /// - A `Vec<u8>` containing the raw byte representation of the packet.
    fn serialize(&self, packet: &ParsedPacket) -> Vec<u8>;
}