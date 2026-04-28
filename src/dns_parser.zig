const std = @import("std");
const dns = @import("dns.zig");

const DnsQuestion = dns.DnsQuestion;
const DnsHeader = dns.DnsHeader;
const QType = dns.QType;

pub const ParseError = error{
    PacketTooShort,
    NoQuestions,
    InvalidPoint,
    InvalidLabel,
    Truncated,
    NameTooLong,
    MissingQType,
    MissingQClass,
    InvalidResponse,
    BufferTooSmall,
};

// DNS 报文格式 RFC 1035
//+---------------------+
//|        Header       |  ← 固定 12 字节
//+---------------------+
//|       Question      |  ← 可变长度（至少 1 个）
//+---------------------+
//|        Answer       |  ← 可变（响应时有）
//+---------------------+
//|   Authority (NS)    |  ← 可变（可选）
//+---------------------+
//|   Additional (AR)   |  ← 可变（可选）
//+---------------------+

pub fn parseByte2DnsQuestion(packet: []const u8, out_question: *DnsQuestion) !void {
    if (packet.len < @sizeOf(DnsHeader)) return error.PacketTooShort;

    const packet_ptr = packet.ptr;

    // 解析到结构体
    const header_ptr: *align(1) const DnsHeader = @ptrCast(packet_ptr);
    const header = header_ptr.*;

    if (header.qdcount == 0) return error.NoQuestions;

    // 解析question部分结构
    // 第一个字节就是域名长度
    var offset: usize = @sizeOf(DnsHeader);

    // 域名缓冲区长度
    var domain_buf: [255]u8 = undefined;
    var domain_len: u8 = 0;
    var jumps: usize = 0; // DNS请求包存在压缩指针攻击的情况，jumps位限定压缩指针跳转次数

    // 域名解析
    while (offset < packet.len and jumps < 8) {
        // 域名结构大抵是这样的：
        // www.4399.com
        // [3][w][w][w][4][4][3][9][9][3][c][o][m]
        // 每个'.'用来分隔label, 每个label开头第一个字符就是域名长度
        const label_len = packet[offset];

        // 偏移到第一个有效域名字符开始
        offset += 1;

        // 域名字段以0结束
        if (label_len == 0) break;

        // 特殊的一类字段：压缩指针
        if ((label_len & 0b1100_0000) != 0) {
            // 占2字节，高2位固定11
            // 后14字节为偏移地址
            if (offset >= packet.len) return error.InvalidPoint;
            // 取出2字节，去掉高2位
            const ptr = (@as(u16, (label_len & 0b0011_1111)) << 8) | @as(u16, packet[offset]);
            offset = @intCast(ptr);
            jumps += 1;
            continue;
        }

        // 压缩指针给出的最大偏移值就是域名label的最大长度2^6-1=63
        if (label_len > 63) return error.InvalidLabel;
        if (offset + label_len > packet.len) return error.Truncated;

        if (domain_len > 0) {
            if (domain_len > domain_buf.len) return error.NameTooLong;
            // 分隔label
            domain_buf[domain_len] = '.';
            domain_len += 1;
        }

        if (domain_len + label_len > domain_buf.len) return error.NameTooLong;

        @memcpy(
            domain_buf[domain_len..][0..label_len],
            packet[offset .. offset + label_len],
        );
        domain_len += label_len;
        offset += label_len;
    }

    if (offset + 2 > packet.len) return error.MissingQType;

    // 转换指针类型
    const qtype_raw_ptr: *align(1) const u16 = @ptrCast(&packet[offset]);
    // 解引用
    const qtype_raw = @as(u16, @byteSwap(qtype_raw_ptr.*));

    const qtype: QType = @enumFromInt(qtype_raw);

    out_question.* = DnsQuestion{
        .domain = domain_buf,
        .domain_len = domain_len,
        .qtype = qtype,
    };
}

/// encodeName 将点分域名编码为 DNS 格式
/// 输入: "www.example.com"
/// 输出: [3] 'w' 'w' 'w' [7] 'e' 'x' 'a' 'm' 'p' 'l' 'e' [3] 'c' 'o' 'm' [0]
pub fn encodeName(domain: []const u8, buf: []u8) !usize {
    var domain_seg = std.mem.splitAny(u8, domain, ".");
    var buf_offset = 0;
    while (domain_seg.next()) |segment| {
        const seg_len = segment.len;
        if (seg_len > 63) return error.NameTooLong;
        if (buf_offset + 1 + seg_len > buf.len) return error.NameTooLong;

        buf[buf_offset] = @as(u8, seg_len);
        buf_offset += 1;

        @memcpy(buf[buf_offset..][0..seg_len], segment);
        buf_offset += seg_len;
    }

    buf[buf_offset] = 0; // end

    return buf_offset;
}

/// buildResponse 构建 DNS 响应
/// 将查询包转换为一个基本的响应（只设置 QR=1, AA=1）
pub fn buildResponse(query: []const u8, buf: []u8) !usize {
    if (query.len < @sizeOf(DnsHeader)) return error.PacketTooShort;
    if (buf.len < query.len) return error.BufferTooSmall;

    @memcpy(buf[0..query.len], query);

    const header_ptr: *align(1) DnsHeader = @ptrCast(buf.ptr);
    header_ptr.flags = std.mem.readInt(u16, query[2..4], .big);
    header_ptr.flags |= 0b1000_0000_0000_0000; // 设置QR=1

    return query.len;
}
