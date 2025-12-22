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
    name: [255]u8,
    name_len: u8,
    qtype: QType,
};
