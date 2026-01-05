use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Root configuration structure
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    /// List of flows to generate (can be multiple versions)
    #[serde(default)]
    pub flows: Vec<FlowConfig>,

    /// Destination for UDP transmission
    #[serde(default)]
    pub destination: Destination,
}

/// Flow configuration (version-specific)
#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "version")]
pub enum FlowConfig {
    #[serde(rename = "v5")]
    V5(V5Config),
    #[serde(rename = "v7")]
    V7(V7Config),
    #[serde(rename = "v9")]
    V9(V9Config),
    #[serde(rename = "ipfix")]
    IPFix(IPFixConfig),
}

// ============================================================================
// NetFlow V5 Configuration
// ============================================================================

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct V5Config {
    /// Optional header fields (auto-generated if not specified)
    #[serde(default)]
    pub header: Option<V5Header>,

    /// Flow records
    pub flowsets: Vec<V5FlowSet>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct V5Header {
    pub unix_secs: Option<u32>,
    pub unix_nsecs: Option<u32>,
    pub sys_up_time: Option<u32>,
    pub flow_sequence: Option<u32>,
    pub engine_type: Option<u8>,
    pub engine_id: Option<u8>,
    pub sampling_interval: Option<u16>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct V5FlowSet {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub first: u32,
    pub last: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub tcp_flags: u8,
    pub protocol: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
}

// ============================================================================
// NetFlow V7 Configuration
// ============================================================================

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct V7Config {
    /// Optional header fields (auto-generated if not specified)
    #[serde(default)]
    pub header: Option<V7Header>,

    /// Flow records
    pub flowsets: Vec<V7FlowSet>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct V7Header {
    pub unix_secs: Option<u32>,
    pub unix_nsecs: Option<u32>,
    pub sys_up_time: Option<u32>,
    pub flow_sequence: Option<u32>,
    pub reserved: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct V7FlowSet {
    pub src_addr: Ipv4Addr,
    pub dst_addr: Ipv4Addr,
    pub next_hop: Ipv4Addr,
    pub input: u16,
    pub output: u16,
    pub d_pkts: u32,
    pub d_octets: u32,
    pub first: u32,
    pub last: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub flags: u8,
    pub tcp_flags: u8,
    pub protocol: u8,
    pub tos: u8,
    pub src_as: u16,
    pub dst_as: u16,
    pub src_mask: u8,
    pub dst_mask: u8,
    pub flags2: u16,
    pub router_src: Ipv4Addr,
}

// ============================================================================
// NetFlow V9 Configuration
// ============================================================================

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct V9Config {
    /// Optional header fields (auto-generated if not specified)
    #[serde(default)]
    pub header: Option<V9Header>,

    /// Flowsets (templates and data)
    pub flowsets: Vec<V9FlowSet>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct V9Header {
    pub sys_up_time: Option<u32>,
    pub unix_secs: Option<u32>,
    pub sequence_number: Option<u32>,
    pub source_id: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum V9FlowSet {
    #[serde(rename = "template")]
    Template {
        template_id: u16,
        fields: Vec<V9TemplateField>,
    },
    #[serde(rename = "data")]
    Data {
        template_id: u16,
        records: Vec<serde_yaml::Value>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct V9TemplateField {
    pub field_type: String,
    pub field_length: u16,
}

// ============================================================================
// IPFIX Configuration
// ============================================================================

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IPFixConfig {
    /// Optional header fields (auto-generated if not specified)
    #[serde(default)]
    pub header: Option<IPFixHeader>,

    /// Flowsets (templates and data)
    pub flowsets: Vec<IPFixFlowSet>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct IPFixHeader {
    pub export_time: Option<u32>,
    pub sequence_number: Option<u32>,
    pub observation_domain_id: Option<u32>,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
#[serde(tag = "type")]
pub enum IPFixFlowSet {
    #[serde(rename = "template")]
    Template {
        template_id: u16,
        fields: Vec<IPFixTemplateField>,
    },
    #[serde(rename = "data")]
    Data {
        template_id: u16,
        records: Vec<serde_yaml::Value>,
    },
}

#[derive(Debug, Deserialize, Serialize, Clone, PartialEq)]
pub struct IPFixTemplateField {
    pub field_type: String,
    pub field_length: u16,
}

// ============================================================================
// Destination Configuration
// ============================================================================

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Destination {
    #[serde(default = "default_ip")]
    pub ip: String,

    #[serde(default = "default_port")]
    pub port: u16,
}

impl Default for Destination {
    fn default() -> Self {
        Destination {
            ip: default_ip(),
            port: default_port(),
        }
    }
}

fn default_ip() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    2055
}
