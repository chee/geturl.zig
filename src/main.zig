const std = @import("std");
const path = std.fs.path;
const requestz = @import("requestz");
const getseq = @import("getseq");
const mimetypes = @import("mimetypes");
const pcre = @import("pcre");

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

// TODO utf-8
fn slugify(string: []const u8) ![256]u8 {
    const replaceables = try pcre.compile("[^a-zA-Z0-9.-]+", .{});
    defer replaceables.deinit();
    var buf: [256]u8 = undefined;
    _ = try pcre.replace(replaceables, string, 0, "-", &buf, .{});
    return buf;
}

test "slugify works with basic strings" {
    try std.testing.expectEqual("hello there darling", slugify("hello there darling", "hello-there-darling"));
}

test "slugify works with unicode strings" {
    try std.testing.expectEqual("hello there bebé", slugify("hello there bebé", "hello-there-beb-"));
}

test "slugify works with long strings" {
    try std.testing.expectEqual("really long, really longreally long, really longreally long, really longreally long, really longreally long, really long", slugify("really long, really longreally long, really longreally long, really longreally long, really longreally long, really long", "really-long-really-longreally-long-really-longreally-long-really-longreally-long-really-longreally-long-really-long"));
}

test "slugify works with fancy strings" {}

pub fn main() anyerror!void {
    // const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    // throw myself away
    _ = args.next();

    var mimes = mimetypes.Registry.init(std.heap.page_allocator);
    defer mimes.deinit();
    try mimes.load();

    // TODO accept this case if we are being piped into
    const filename = args.next() orelse {
        die(GeturlError.NoFilename);
        return "";
    };

    // TODO if filename is /dev/fd/* or /tmp/.psub* guess extension using mimes
    const basename = path.basename(filename);
    const extension = path.extension(basename);

    // TODO extract slugify to lib
    const output_filename = slugify(basename);

    std.log.info("filename: {s}", .{filename});
    std.log.info("basename: {s}", .{basename});
    std.log.info("extension: {s}", .{extension});
    std.log.info("output_filename: {s}", .{output_filename});
}
