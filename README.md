# pcre2zig
A simple Zig API for the PCRE2 C library.

## Sample Usage
In lack of proper docs, the following test samples show how to use the library. Some functions and methods may take bit 
flags as options (bitwise `or`ed into a u32); please refer to the [PCRE2 docs](https://www.pcre.org/current/doc/html/)
for details on these options.

```zig
const std = @import("std");

const p2z = @import("pcre2zig");

test "pcre2zig simple match" {
    const code = try p2z.compile("ab+c", .{});
    defer code.deinit();
    _ = code.jitCompile(0);
    const data = try p2z.MatchData.init(code);
    defer data.deinit();

    try std.testing.expect(try p2z.match(code, "abc", 0, data, .{}));
    try std.testing.expect(try p2z.match(code, "abbbbc", 0, data, .{}));
    try std.testing.expect(!try p2z.match(code, "acb", 0, data, .{}));
}

test "pcre2zig match iterator" {
    const pattern =
        \\(?x) (?<one> \d{3}) - (?<two> \d{3}) - (?<three> \d{4})
    ;
    const subject = "Tel: 111-123-4567 Tel: 222-234-5678 Tel: 333-456-7890";

    const code = try p2z.compile(pattern, .{});
    defer code.deinit();
    _ = code.jitCompile(0);
    const data = try p2z.MatchData.init(code);
    defer data.deinit();

    try std.testing.expect(try p2z.match(code, subject, 0, data, .{}));

    var iter = p2z.MatchIterator.init(code, data, subject);

    try std.testing.expect(try iter.next());
    try std.testing.expectEqualStrings("123", p2z.numberedCapture(data, subject, 2).?);
    try std.testing.expectEqualStrings("4567", p2z.namedCapture(code, data, subject, "three").?);

    try std.testing.expect(try iter.next());
    try std.testing.expectEqualStrings("234", p2z.numberedCapture(data, subject, 2).?);
    try std.testing.expectEqualStrings("5678", p2z.namedCapture(code, data, subject, "three").?);

    try std.testing.expect(try iter.next());
    try std.testing.expectEqualStrings("456", p2z.numberedCapture(data, subject, 2).?);
    try std.testing.expectEqualStrings("7890", p2z.namedCapture(code, data, subject, "three").?);

    try std.testing.expect(!try iter.next());
    iter.reset();

    try std.testing.expect(try iter.next());
    try std.testing.expectEqualStrings("123", p2z.numberedCapture(data, subject, 2).?);
    try std.testing.expectEqualStrings("4567", p2z.namedCapture(code, data, subject, "three").?);
}

test "pcre2zig replace" {
    const pattern =
        \\(?x) (?<month> \d{2}) / (?<day> \d{2}) / (?<year> \d{4})
    ;
    const subject = "Date: 12/25/1970 Date: 11/24/1969";
    const replacement =
        \\${year}/${month}/${day}
    ;

    const code = try p2z.compile(pattern, .{});
    defer code.deinit();
    _ = code.jitCompile(0);
    const data = try p2z.MatchData.init(code);
    defer data.deinit();
    var buf: [256]u8 = undefined;

    try std.testing.expectEqualStrings("Date: 1970/12/25 Date: 11/24/1969", try p2z.replace(
        code,
        subject,
        0,
        replacement,
        &buf,
        .{},
    ));
    try std.testing.expectEqualStrings("Date: 1970/12/25 Date: 1969/11/24", try p2z.replace(
        code,
        subject,
        0,
        replacement,
        &buf,
        .{ .bits = p2z.pcre2.PCRE2_SUBSTITUTE_GLOBAL },
    ));
}

test "pcre2zig code copy" {
    const pattern =
        \\(?x) a (?<bees> b+) c
    ;
    const code = try p2z.compile(pattern, .{});
    defer code.deinit();
    const data = try p2z.MatchData.init(code);
    defer data.deinit();
    const code_copy = try code.copy();
    defer code_copy.deinit();

    try std.testing.expect(try p2z.match(code_copy, "abc", 0, data, .{}));
    try std.testing.expect(try p2z.match(code_copy, "abbbbc", 0, data, .{}));
    try std.testing.expectEqualStrings("bbbb", p2z.namedCapture(code_copy, data, "abbbbc", "bees").?);
    try std.testing.expect(!try p2z.match(code_copy, "acb", 0, data, .{}));
}
```

