const std = @import("std");
const dns_parser = @import("dns_parser.zig");
const dns = @import("dns.zig");
const log = @import("log.zig");

const io = std.Io;
const net = std.Io.net;

const DnsQuestion = dns.DnsQuestion;

pub fn main() !void {
    // Prints to stderr, ignoring potential errors.
    std.debug.print("welcome using DNZmasq.\n", .{});

    const sock_addr = io.net.IpAddress.parse("0.0.0.0", 54) catch unreachable;

    const sock = try sock_addr.bind(&sock_addr, io, .{});

    var recv_buf: [512]u8 = undefined;

    while (true) {
        const revc = sock.receive(io, &recv_buf) catch continue;
        const packet = revc.data;

        const question: DnsQuestion = undefined;
        if (dns_parser.parseByte2DnsQuestion(&packet, &question)) |_| {
            log.logQuery(revc.from, &question);
        } else |_| {
            continue;
        }
    }
}
