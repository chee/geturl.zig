const std = @import("std");

const consonants = [_]u8{ 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'y', 'z' };
const vowels = [_]u8{ 'a', 'e', 'i', 'o', 'u' };

fn consonant() u8 {
    return consonants[std.crypto.random.int(u8) % consonants.len];
}

fn vowel() u8 {
    return vowels[std.crypto.random.int(u8) % vowels.len];
}

fn word() std.fmt.BufPrintError![5]u8 {
    var w: [5]u8 = undefined;
    _ = try std.fmt.bufPrint(&w, "{c}{c}{c}{c}{c}", .{
        consonant(),
        vowel(),
        consonant(),
        vowel(),
        consonant()
    });
    return w;
}

pub fn main() anyerror!void {
    const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    _ = args.next();

    var times = std.fmt.parseInt(u32, args.next() orelse "1", 0) catch 1;

    while (times > 0) : (times -= 1) {
        try stdout.print("{s}", .{word()});
        if (times > 1) {
            _ = try stdout.write("-");
        }
    }
    _ = try stdout.write("\n");
}
