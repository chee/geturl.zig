const std = @import("std");

const pcre2 = @cImport({
    @cDefine("PCRE2_CODE_UNIT_WIDTH", "8");
    @cInclude("pcre2.h");
});

/// `CompiledCode` is produced by a call to `compile`. Use `deinit` to free its resources when done.
pub const CompiledCode = struct {
    ptr: *pcre2.pcre2_code_8,

    pub fn deinit(self: CompiledCode) void {
        pcre2.pcre2_code_free_8(self.ptr);
    }
};

/// Only necessary when calling `compile` in special cases. See the PCRE2 docs for `pcre2_compile` to learn more.
pub const CompileContext = pcre2.pcre2_compile_context_8;

// Convenience struct for the options used by `compile`.
pub const CompileOptions = struct {
    bits: u32 = 0,
    context_opt_ptr: ?*CompileContext = null,
};

/// Compiles a regular expression pattern. Caller must call `deinit` on the returned `CompiledCode`.
pub fn compile(pattern: []const u8, options: CompileOptions) PcreError!CompiledCode {
    var err_code: i32 = 0;
    var err_offset: usize = 0;

    var re_opt_ptr = pcre2.pcre2_compile_8(
        pattern.ptr,
        pattern.len,
        options.bits,
        &err_code,
        &err_offset,
        options.context_opt_ptr,
    );

    if (re_opt_ptr == null) {
        var buf: [256]u8 = [_]u8{0} ** 256;
        _ = pcre2.pcre2_get_error_message_8(err_code, &buf, buf.len);
        std.log.debug("pcre2zig.compile error at pattern offset {}: {s}", .{ err_offset, &buf });
        return error.CompileFailed;
    }

    return CompiledCode{ .ptr = re_opt_ptr.? };
}

/// Only necessary when calling `match` in special cases. See the PCRE2 docs for `pcre2_match` to learn more.
pub const MatchContext = pcre2.pcre2_match_context_8;

/// Resources used by `match` are stored in `MatchData`. Call `deinit` to free them.
pub const MatchData = struct {
    ptr: *pcre2.pcre2_match_data_8,

    pub fn init(code: CompiledCode) PcreError!MatchData {
        const opt_ptr = pcre2.pcre2_match_data_create_from_pattern_8(code.ptr, null); //TODO: Handle context arg.
        if (opt_ptr == null) return error.MatchDataCreateFailed;
        return MatchData{ .ptr = opt_ptr.? };
    }

    pub fn deinit(self: MatchData) void {
        pcre2.pcre2_match_data_free_8(self.ptr);
    }
};

// Convenience struct for the options used by `match`.
pub const MatchOptions = struct {
    bits: u32 = 0,
    context_opt_ptr: ?*MatchContext = null,
};

pub fn match(
    code: CompiledCode,
    subject: []const u8,
    start_offset: usize,
    data: MatchData,
    options: MatchOptions,
) PcreError!bool {
    var rc = pcre2.pcre2_match_8(
        code.ptr,
        subject.ptr,
        subject.len,
        start_offset,
        options.bits,
        data.ptr,
        options.context_opt_ptr,
    );

    if (rc < 0) {
        // Match failed; determine if no-match or eror.
        switch (rc) {
            pcre2.PCRE2_ERROR_NOMATCH => return false,
            else => {
                std.log.debug("pcre2zig.match error: {}", .{rc});
                return error.MatchError;
            },
        }
    }

    return true;
}

pub const PcreError = error{
    CompileFailed,
    MatchDataCreateFailed,
    MatchError,
};

test "pcre2zig simple match" {
    const code = try compile("ab+c", .{});
    defer code.deinit();
    const data = try MatchData.init(code);
    defer data.deinit();

    try std.testing.expect(try match(code, "abc", 0, data, .{}));
    try std.testing.expect(try match(code, "abbbbc", 0, data, .{}));
    try std.testing.expect(!try match(code, "acb", 0, data, .{}));
}
