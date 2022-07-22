const std = @import("std");
const path = std.fs.path;
const getseq = @import("getseq");
//const mimetypes = @import("mimetypes");

const GeturlError = error{NoFilename};

const usage = "usage <geturl file>\n";

fn die(err: GeturlError) noreturn {
    const stderr = std.io.getStdErr().writer();
    const msg = switch (err) {
        GeturlError.NoFilename => "error: no filename",
        else => "",
    };
    _ = stderr.write(msg) catch {};
    _ = stderr.write("\n") catch {};
    std.process.exit(1);
}
fn slugify(string: []const u8, allocator: std.mem.Allocator) ![]u8 {
    const view = std.unicode.Utf8View.init(string) catch unreachable;
    var iter = view.iterator();
    const memory = try allocator.alloc(u8, string.len + 1);
    var len: usize = 0;
    while (iter.nextCodepoint()) |c| {
        const ch: u8 = @truncate(u8, c);
        if (c <= 0xff and (std.ascii.isAlNum(ch) or ch == '.')) {
            memory[len] = ch;
            len += 1;
        } else {
            if (len > 0 and memory[len - 1] == '-') {
                continue;
            } else {
                memory[len] = '-';
                len += 1;
            }
        }
    }
    return memory[0..len];
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alligator = arena.allocator();
    const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    // throw myself away
    _ = args.next();

    // var mimes = mimetypes.Registry.init(alligator);
    // try mimes.load();

    // TODO accept this case if we are being piped into
    const filename = args.next() orelse {
        die(GeturlError.NoFilename);
        return "";
    };

    // TODO if filename is /dev/fd/* or /tmp/.psub* guess extension using mimes
    const basename = path.basename(filename);

    const output_filename = slugify(basename, alligator) catch unreachable;
    const dir = getseq.word();
    const destdir = std.fmt.allocPrint(alligator, "/blog/files/{s}", .{dir}) catch unreachable;
    var ssh = std.ChildProcess.init(&.{ "ssh", "snoot", "mkdir", "-p", destdir }, alligator);
    _ = try ssh.spawnAndWait();

    const remote = std.fmt.allocPrint(alligator, "chee@snoot:{s}/{s}", .{ destdir, output_filename }) catch unreachable;
    const public = std.fmt.allocPrint(alligator, "https://chee.party/files/{s}/{s}", .{ dir, output_filename }) catch unreachable;

    var rsync = std.ChildProcess.init(&.{ "rsync", "-zL", "--progress", "--chmod", "a+rw", filename, remote }, alligator);

    _ = try rsync.spawnAndWait();

    try stdout.print("{s}\n", .{public});
}
