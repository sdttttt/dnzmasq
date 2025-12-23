const std = @import("std");
const net = std.Io.net;
const DnsQuestion = @import("dns.zig");

pub fn logQuery(client_addr: net.IpAddress, question: *const DnsQuestion) void {
    // 手动拼接字符串，避免 fmt.allocPrint
    const name_slice = question.name[0..question.name_len];
    const type_str = switch (question.qtype) {
        .A => "A",
        .AAAA => "AAAA",
        .CNAME => "CNAME",
        .TXT => "TXT",
        .MX => "MX",
        else => "OTHER",
    };

    // 写入 stderr（路由器通常重定向到 syslog）
    const prefix = "DNS QUERY: ";
    _ = std.os.write(std.io.tty_stderr_fileno, prefix) catch {};

    // 打印客户端 IP
    var ip_buf: [16]u8 = undefined;
    const ip_str = client_addr.address.toString(ip_buf[0..]);
    _ = std.os.write(std.io.tty_stderr_fileno, ip_str) catch {};

    const sep = " -> ";
    _ = std.os.write(std.io.tty_stderr_fileno, sep) catch {};

    // 打印域名
    _ = std.os.write(std.io.tty_stderr_fileno, name_slice) catch {};

    const space = " (";
    _ = std.os.write(std.io.tty_stderr_fileno, space) catch {};
    _ = std.os.write(std.io.tty_stderr_fileno, type_str) catch {};
    const close = ")\n";
    _ = std.os.write(std.io.tty_stderr_fileno, close) catch {};
}
