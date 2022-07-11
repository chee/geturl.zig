const std = @import("std");

const consonants = [_]u8{ 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z' };
const vowels = [_]u8{'a', 'e', 'i', 'o', 'u'};

fn word() [5]u8 {
    var buffer: [5]u8 = undefined;

    var i: u8 = 5;

    while (i > 0) {
        const int = std.crypto.random.int(u8);
        buffer[i - 1] =
            if (i % 2 == 0)
                consonants[int % consonants.len]
            else
                vowels[int % vowels.len];
        i -= 1;
    }

    return buffer;
}

pub fn main() anyerror!void {
    const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    _ = args.next();

    var times = std.fmt.parseInt(u32, args.next() orelse "1", 0) catch 1;

    while (times > 0) {
        try stdout.print("{s}", .{word()});
        times -= 1;
        if (times > 0) {
            _ = try stdout.write("-");
        }
    }
    _ = try stdout.write("\n");
}
