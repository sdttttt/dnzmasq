const std = @import("std");

pub const ListenConfig = struct {
    address: []const u8, // "0.0.0.0" 或 "::"
    port: u16, // 53
};

pub const UpstreamServer = struct {
    address: []const u8, // "8.8.8.8" 或 "1.1.1.1"
    port: u16, // 53
};

pub const CacheConfig = struct {
    enabled: bool,
    min_ttl: u32, // 最小 TTL（秒）
    max_ttl: u32, // 最大 TTL（秒）
    negative_ttl: u32, // NXDOMAIN 缓存时间（秒）
    max_entries: usize, // 最大缓存条目数
};

pub const LogLevel = enum {
    debug,
    info,
    warn,
    err,
};

pub const AppConfig = struct {
    listen: ListenConfig,
    upstream_servers: *const [2]UpstreamServer,
    cache: CacheConfig,
    log_level: LogLevel,

    const Self = @This();

    pub fn default() Self {
        return .{ .listen = .{
            .address = "0.0.0.0",
            .port = 53,
        }, .upstream_servers = &.{ .{ .address = "8.8.8.8", .port = 53 }, .{ .address = "1.1.1.1", .port = 53 } }, .cache = .{
            .enabled = true,
            .min_ttl = 60,
            .max_ttl = 3600,
            .negative_ttl = 300,
            .max_entries = 4096,
        }, .log_level = .info };
    }

    pub fn fromEnv() !Self {
        var config = Self.default();
        var env_map = try std.process.getEnvMap(std.heap.page_allocator);
        defer env_map.deinit();

        // 1. 解析日志级别（字符串 → 枚举）
        if (env_map.get("DNZ_LOG_LEVEL")) |val| {
            if (std.meta.stringToEnum(LogLevel, val)) |level| {
                config.log_level = level;
            }
        }
        // 2. 解析端口号
        if (env_map.get("DNZ_PORT")) |val| {
            config.listen.port = std.fmt.parseInt(u16, val, 10) catch 53;
        }
        // 3. 缓存开关
        if (env_map.get("DNZ_CACHE")) |val| {
            config.cache.enabled = std.mem.eql(u8, val, "1") or std.mem.eql(u8, val, "true");
        }
        return config;
    }

    pub fn print(self: *Self) void {
        std.debug.print("{s}:{d}\n", .{ self.listen.address, self.listen.port });
    }
};
