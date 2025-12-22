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

pub fn parseByte2DnsQuestion(packet: []const u8, out_question: *DnsQuestion) !void {
    if (packet.len < @sizeOf(DnsHeader)) return error.PacketTooShort;

    // 解析到结构体
    const header = @as(*align(1) const DnsHeader, @ptrFromInt(packet.ptr)).*;

    if (header.qdcount == 0) return error.NoQuestions;

    // 头结束开始
    var offset = @sizeOf(DnsHeader);

    var name_buf: [255]u8 = undefined;
    var name_len: usize = 0;
    var jumps: usize = 0;

    while (offset < packet.len and jumps < 10) {
        const label_len = packet[offset];
        offset += 1;

        if (label_len == 0) break;

        if ((label_len & 0b1100_0000) != 0) {
            // 压缩指针

        }
    }
}
