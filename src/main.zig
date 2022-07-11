const std = @import("std");

const alphabet = [_]u8{ 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z' };

pub fn word() [5]u8 {
    var buffer: [5]u8 = undefined;

    var i: u8 = 5;
    while (i > 0) {
        buffer[i - 1] = alphabet[std.crypto.random.int(u8) % alphabet.len];
        i -= 1;
    }

    return buffer;
}

pub fn main() anyerror!void {
    const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    _ = args.next();
    const arg = args.next() orelse "5";
    var times = std.fmt.parseInt(u32, arg, 0) catch 5;
    
    while (times > 0) {
        try stdout.print("{s}", .{word()});
        times -= 1;
        if (times > 0) {
            _ = try stdout.write("-");
        }
    }
    _ = try stdout.write("\n");
}
