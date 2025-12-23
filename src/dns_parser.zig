const std = @import("std");
const dns = @import("dns.zig");

const DnsQuestion = dns.DnsQuestion;
const DnsHeader = dns.DnsHeader;
const QType = dns.QType;

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

pub fn parseByte2DnsQuestion(packet: *const []u8, out_question: *DnsQuestion) !void {
    if (packet.len < @sizeOf(DnsHeader)) return error.PacketTooShort;

    const packet_data = packet.*;
    const packet_data_ptr: [*]const u8 = @ptrCast(packet_data);

    // 解析到结构体
    const header_ptr: *align(1) const DnsHeader = @ptrCast(packet_data_ptr);
    const header = header_ptr.*;

    if (header.qdcount == 0) return error.NoQuestions;

    // 解析question部分结构
    // 第一个字节就是域名长度
    var offset = @sizeOf(DnsHeader);

    var domain_buf: [255]u8 = undefined;
    var domain_len: usize = 0;
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
    const qtype_raw = @as(u16, @byteSwap(@as(*const u16, @ptrFromInt(&packet[offset])).*));
    const qtype = @as(QType, @enumFromInt(qtype_raw)) catch QType.A;

    out_question.* = DnsQuestion{
        .domain = domain_buf,
        .domain_len = domain_len,
        .qtype = qtype,
    };
}
