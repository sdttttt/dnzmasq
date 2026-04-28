pub const CLASS_IN: u16 = 1;
pub const DNS_PORT: u16 = 53;
pub const MAX_DNS_NAME_LEN: u16 = 255;

// DnsHeader 头
pub const DnsHeader = packed struct {
    id: u16,
    flags: u16,
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
};

pub const QType = enum(u16) {
    A = 1,
    NS = 2,
    CNAME = 5,
    SOA = 6,
    PTR = 12,
    MX = 15,
    TXT = 16,
    AAAA = 28,
    SRV = 33,
    NAPTR = 35,
    DS = 43,
    RRSIG = 46,
    DNSKEY = 48,
    _,
};

pub const DnsQuestion = struct {
    domain: [255]u8,
    domain_len: u8,
    qtype: QType,
};

pub const DnsRecord = struct {
    name: []const u8,
    qtype: QType,
    class: u16,
    ttl: u32,
    rdlen: u16,
    rdata: []const u8,
};

pub const DnsMessage = struct {
    header: DnsHeader,
    questions: []DnsQuestion,
    answers: []DnsRecord,
    authorities: []DnsRecord,
    additionals: []DnsRecord,
};
