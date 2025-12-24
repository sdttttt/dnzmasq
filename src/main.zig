const std = @import("std");
const dns_parser = @import("dns_parser.zig");
const dns = @import("dns.zig");

const net = std.Io.net;

const DnsQuestion = dns.DnsQuestion;

pub fn main() !void {
    // Prints to stderr, ignoring potential errors.
    std.debug.print("welcome using DNZmasq.\n", .{});

    const sock_addr = std.Io.net.IpAddress.parse("0.0.0.0", 54) catch unreachable;

    var single_thr: std.Io.Threaded = .init_single_threaded;
    defer single_thr.deinit();

    const sio = single_thr.io();

    const sock = try sock_addr.bind(sio, .{
        .mode = std.Io.net.Socket.Mode.dgram,
    });

    var recv_buf: [512]u8 = undefined;

    while (true) {
        const revc = sock.receive(sio, &recv_buf) catch continue;
        const packet = revc.data;

        var question: DnsQuestion = undefined;
        if (dns_parser.parseByte2DnsQuestion(packet, &question)) |_| {
            std.debug.print("dns coming...", .{});
        } else |_| {
            continue;
        }
    }
}
