const std = @import("std");
const path = std.fs.path;
const mem = std.mem;
const getseq = @import("getseq");
const usage = "usage <geturl file>\n";

// TODO handle errors lol

fn slugify(string: []const u8, allocator: mem.Allocator) ![]u8 {
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

fn starts_with(string: []const u8, sub: []const u8, alligator: mem.Allocator) bool {
    if (sub.len > string.len) {
        return false;
    }
    var start = std.ArrayList(u8).init(alligator);
    defer start.deinit();
    start.appendSlice(string[0..sub.len]) catch unreachable;
    return mem.eql(u8, start.items, sub);
}

test "starts_with works" {
    try std.testing.expect(starts_with("hello", "h", std.testing.allocator));
    try std.testing.expect(starts_with("hello", "hell", std.testing.allocator));
    try std.testing.expect(!starts_with("hello", "x", std.testing.allocator));
}

fn is_psub(filename: []const u8, alligator: mem.Allocator) bool {
    if (starts_with(filename, "/dev/fd/", alligator)) {
        return true;
    }

    const basename = path.basename(filename);

    if (starts_with(basename, ".psub.", alligator)) {
        return true;
    }

    return false;
}

test "is_psub detects posix-style" {
    try std.testing.expect(is_psub("/dev/fd/63", std.testing.allocator));
}

test "is_psub detects fish-style" {
    try std.testing.expect(is_psub("/tmp/.psub.s1d8f", std.testing.allocator));
    try std.testing.expect(is_psub("/var/folders/lp/062xjxk50xn_6wwb94dzl5fm0000gn/T//.psub.s8crbTB2un", std.testing.allocator));
}

test "is_psub returns false for other stuff" {
    try std.testing.expect(!is_psub("/tmp/honk", std.testing.allocator));
    try std.testing.expect(!is_psub("psub", std.testing.allocator));
}

fn contains(string: []const u8, char: u8) bool {
    for (string) |c| {
        if (c == char) {
            return true;
        }
    }

    return false;
}

test "contains returns true for matches" {
    try std.testing.expect(contains("/tmp/honk", 't'));
}

test "contains returns false for non-matches" {
    try std.testing.expect(!contains("/tmp/honk", 'z'));
}

fn make_filename_for_psub(filename: []const u8, alligator: mem.Allocator) []u8 {
    const result = std.ChildProcess.exec(.{ .allocator = alligator, .argv = &.{ "file", "-b", "--extension", filename } }) catch unreachable;
    var name = std.ArrayList(u8).init(alligator);
    defer name.deinit();
    const word = getseq.word() catch unreachable;
    name.appendSlice(word[0..]) catch unreachable;

    if (mem.eql(u8, result.stdout, "???")) {
        name.appendSlice(".txt") catch unreachable;
    } else if (contains(result.stdout, '/')) {
        var tokens = mem.tokenize(u8, result.stdout, "/");
        const ext = tokens.next() orelse "txt";
        name.append('.') catch unreachable;
        name.appendSlice(ext) catch unreachable;
    } else {
        name.append('.') catch unreachable;
        name.appendSlice(result.stdout) catch unreachable;
    }

    return (name.clone() catch unreachable).items;
}

pub fn main() anyerror!void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alligator = arena.allocator();
    const stdout = std.io.getStdOut().writer();

    var args = std.process.args();
    // throw myself away
    _ = args.next();

    // TODO accept this case if we are being piped into
    const filename = args.next() orelse unreachable;
    // var suck_from_pipe = false;

    const basename = if (is_psub(filename, alligator))
        make_filename_for_psub(filename, alligator)
    else
        path.basename(filename);

    const output_filename = slugify(basename, alligator) catch unreachable;
    const dir = getseq.word();

    const remote = std.fmt.allocPrint(alligator, "chee@snoot:/blog/files/{s}/{s}", .{ dir, output_filename }) catch unreachable;
    const public = std.fmt.allocPrint(alligator, "https://chee.party/files/{s}/{s}", .{ dir, output_filename }) catch unreachable;

    var rsync = std.ChildProcess.init(&.{ "rsync", "-zL", "--progress", "--mkpath", "--chmod", "a+rw", filename, remote }, alligator);
    rsync.stderr_behavior = std.ChildProcess.StdIo.Ignore;
    _ = try rsync.spawnAndWait();

    try stdout.print("{s}\n", .{public});
}
