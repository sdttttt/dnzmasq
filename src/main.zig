const std = @import("std");
const net = std.Io.net;

pub fn main() !void {
    // Prints to stderr, ignoring potential errors.
    std.debug.print("welcome using DNZmasq.\n", .{});
}
