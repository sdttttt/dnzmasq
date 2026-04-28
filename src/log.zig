const std = @import("std");
const net = std.Io.net;
const DnsQuestion = @import("dns.zig");

pub fn logQuery(client_addr: net.IpAddress, question: *const DnsQuestion) void {
    // 手动拼接字符串，避免 fmt.allocPrint
    const name_slice = question.domain[0..question.domain_len];
    const type_str = switch (question.qtype) {
        .A => "A",
        .AAAA => "AAAA",
        .CNAME => "CNAME",
        .TXT => "TXT",
        .MX => "MX",
        else => "OTHER",
    };

    std.debug.print("DNS QUERY: {} -> {s} ({s})\n", .{
        client_addr,
        name_slice,
        type_str,
    });

    return;
}

pub fn logResponse(client_addr: net.IpAddress, question: *const DnsQuestion, answer_count: u16) void {
    const name_slice = question.domain[0..question.domain_len];
    const type_str = switch (question.qtype) {
        .A => "A",
        .AAAA => "AAAA",
        .CNAME => "CNAME",
        .TXT => "TXT",
        .MX => "MX",
        else => "OTHER",
    };

    std.debug.print("DNS RESPONSE: {} -> {s} ({s}), answers: {}\n", .{
        client_addr,
        name_slice,
        type_str,
        answer_count,
    });
}
