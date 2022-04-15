//! pcre2zig provides a simple Zig API for the PCRE2 C library. Please refer to the PCRE2 docs for detauls on the options
//! that are sometimes available when compiling, matching, and replacing: https://www.pcre.org/current/doc/html/ .

const std = @import("std");

pub const pcre2 = @cImport({
    @cDefine("PCRE2_CODE_UNIT_WIDTH", "8");
    @cInclude("pcre2.h");
});

/// `CompiledCode` is produced by a call to `compile`. Use `deinit` to free its resources when done.
pub const CompiledCode = struct {
    is_crlf: bool = false,
    is_utf8: bool = false,
    name_count: usize = 0,
    name_entry_size: usize = 0,
    name_table_ptr: ?[*]u8 = null,
    ptr: *pcre2.pcre2_code_8,

    pub fn deinit(self: CompiledCode) void {
        pcre2.pcre2_code_free_8(self.ptr);
    }

    /// Returns an independent, deep copy. Does not JIT compile the resulting copy.
    pub fn copy(self: CompiledCode) PcreError!CompiledCode {
        const copy_opt_ptr = pcre2.pcre2_code_copy_8(self.ptr);
        if (copy_opt_ptr == null) return error.CopyingCompiledCode;
        var new_code = self;
        new_code.ptr = copy_opt_ptr.?;
        var name_table_addr: usize = 0;
        _ = pcre2.pcre2_pattern_info_8(
            new_code.ptr,
            pcre2.PCRE2_INFO_NAMETABLE,
            &name_table_addr,
        );
        new_code.name_table_ptr = @intToPtr([*]u8, name_table_addr);

        return new_code;
    }

    /// If JIT compilation is available and successful, returns true, otherwise false and emits a debug log message with
    /// the returned error code. If JIT compilation fails, the `CompiledCode` still can match via interpreter mode, so
    /// failure here needn't be a fatal error. See the PCRE2 docs for more details.
    pub fn jitCompile(self: CompiledCode, options: u32) bool {
        const jit_options = if (options != 0) options else pcre2.PCRE2_JIT_COMPLETE | pcre2.PCRE2_JIT_PARTIAL_HARD | pcre2.PCRE2_JIT_PARTIAL_SOFT;
        const jit_error = pcre2.pcre2_jit_compile_8(self.ptr, jit_options);

        if (jit_error != 0) {
            std.log.debug("pcre2zig.CompiledCode.jitCompile failed: {}", .{jit_error});
            return false;
        }

        return true;
    }

    /// Returns the index number of a named capture group, if defined.
    pub fn nameToNumber(self: CompiledCode, name: []const u8) ?usize {
        if (self.name_table_ptr == null) return null;

        var ptr_copy = self.name_table_ptr.?;
        var i: usize = 0;

        return while (i < self.name_count) : (i += 1) {
            const number: u16 = (@as(u16, ptr_copy[0]) << 8) | @as(u16, ptr_copy[1]);
            const capture_name = ptr_copy[2 .. self.name_entry_size - 1];
            if (std.mem.eql(u8, capture_name, name)) break number;
            ptr_copy += self.name_entry_size;
        } else null;
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
        return error.CompilngPattern;
    }

    var self = CompiledCode{ .ptr = re_opt_ptr.? };

    // Get name count.
    _ = pcre2.pcre2_pattern_info_8(
        self.ptr,
        pcre2.PCRE2_INFO_NAMECOUNT,
        &self.name_count,
    );

    if (self.name_count != 0) {
        // Before we can access the substrings, we must extract the table for
        // translating names to numbers, and the size of each entry in the table.
        var name_table_addr: usize = 0;
        _ = pcre2.pcre2_pattern_info_8(
            self.ptr,
            pcre2.PCRE2_INFO_NAMETABLE,
            &name_table_addr,
        );
        self.name_table_ptr = @intToPtr([*]u8, name_table_addr);

        _ = pcre2.pcre2_pattern_info_8(
            self.ptr,
            pcre2.PCRE2_INFO_NAMEENTRYSIZE,
            &self.name_entry_size,
        );
    }

    var option_bits: u32 = 0;
    _ = pcre2.pcre2_pattern_info_8(
        self.ptr,
        pcre2.PCRE2_INFO_ALLOPTIONS,
        &option_bits,
    );
    self.is_utf8 = (option_bits & pcre2.PCRE2_UTF) != 0;

    // Now find the newline convention and see whether CRLF is a valid newline sequence.
    var newline: u32 = 0;
    _ = pcre2.pcre2_pattern_info_8(
        self.ptr,
        pcre2.PCRE2_INFO_NEWLINE,
        &newline,
    );
    self.is_crlf = newline == pcre2.PCRE2_NEWLINE_ANY or
        newline == pcre2.PCRE2_NEWLINE_CRLF or
        newline == pcre2.PCRE2_NEWLINE_ANYCRLF;

    return self;
}

/// Only necessary when calling `match` in special cases. See the PCRE2 docs for `pcre2_match` to learn more.
pub const MatchContext = pcre2.pcre2_match_context_8;

/// Resources used by `match` are stored in `MatchData`. Call `deinit` to free them.
pub const MatchData = struct {
    ptr: *pcre2.pcre2_match_data_8,

    pub fn init(code: CompiledCode) PcreError!MatchData {
        const opt_ptr = pcre2.pcre2_match_data_create_from_pattern_8(code.ptr, null); //TODO: Handle context arg.
        if (opt_ptr == null) return error.CreatingMatchData;
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

/// Matches the compiled pattern in `code` against `subject`, returning true at the first match found. On success, `data`
/// holds the information related to the match, to be used with functions like `namedCapture` and `numberedCapture`, or
/// to create a `MatchIterator`.
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
                return error.Matching;
            },
        }
    }

    return true;
}

/// Iterates through the matches in a subject for a given `CompiledCode` and `MatchData` combination. Each call to 
/// `next` moves to the next match and returns true. If no more matches are found, false is returned. You can then 
/// start over by calling the `reset` method.
pub const MatchIterator = struct {
    code: CompiledCode,
    data: MatchData,
    ovector: ?[*c]usize = null,
    subject: []const u8,

    /// The subject must be the same provided to `match` with the given `MatchData`.
    pub fn init(
        code: CompiledCode,
        data: MatchData,
        subject: []const u8,
    ) MatchIterator {
        return .{
            .code = code,
            .data = data,
            .subject = subject,
        };
    }

    pub fn next(self: *MatchIterator) PcreError!bool {
        if (self.ovector == null) {
            self.ovector = pcre2.pcre2_get_ovector_pointer_8(self.data.ptr);
            return true;
        }

        const subject_len = self.subject.len;
        var options: u32 = 0; //  Normally no options
        var start_offset: usize = self.ovector.?[1]; //  Start at end of previous match

        // If the previous match was for an empty string, we are finished if we are
        // at the end of the subject. Otherwise, arrange to run another match at the
        // same point to see if a non-empty match can be found.
        if (self.ovector.?[0] == self.ovector.?[1]) {
            if (self.ovector.?[0] == subject_len) return false;
            options = pcre2.PCRE2_NOTEMPTY_ATSTART | pcre2.PCRE2_ANCHORED;
        } else {
            // If the previous match was not an empty string, there is one tricky case to
            // consider. If a pattern contains \K within a lookbehind assertion at the
            // start, the end of the matched string can be at the offset where the match
            // started. Without special action, this leads to a loop that keeps on matching
            // the same substring. We must detect this case and arrange to move the start on
            // by one character. The pcre2_get_startchar() function returns the starting
            // offset that was passed to pcre2_match().
            var startchar: usize = pcre2.pcre2_get_startchar_8(self.data.ptr);
            if (start_offset <= startchar) {
                if (startchar >= subject_len) return false; //  Reached end of subject.
                start_offset = startchar + 1; //  Advance by one character.

                //  If UTF-8, it may be more
                if (self.code.is_utf8) {
                    while (start_offset < subject_len) : (start_offset += 1) {
                        if ((self.subject[start_offset] & 0xc0) != 0x80) break;
                    }
                }
            }
        }

        //  Run the next matching operation
        const rc = pcre2.pcre2_match_8(
            self.code.ptr,
            self.subject.ptr,
            subject_len,
            start_offset,
            options,
            self.data.ptr,
            null, //TODO: Handle match context.
        );

        // This time, a result of NOMATCH isn't an error. If the value in "options"
        // is zero, it just means we have found all possible matches, so the loop ends.
        // Otherwise, it means we have failed to find a non-empty-string match at a
        // point where there was a previous empty-string match. In this case, we do what
        // Perl does: advance the matching position by one character, and continue. We
        // do this by setting the "end of previous match" offset, because that is picked
        // up at the top of the loop as the point at which to start again.
        //
        // There are two complications: (a) When CRLF is a valid newline sequence, and
        // the current position is just before it, advance by an extra byte. (b)
        // Otherwise we must ensure that we skip an entire UTF character if we are in
        // UTF mode.
        if (rc == pcre2.PCRE2_ERROR_NOMATCH) {
            if (options == 0) return false; //  All matches found
            self.ovector.?[1] = start_offset + 1; //  Advance one code unit

            if (self.code.is_crlf and //  If CRLF is a newline and
                start_offset < subject_len - 1 and //  we are at CRLF,
                self.subject[start_offset] == '\r' and
                self.subject[start_offset + 1] == '\n')
            {
                self.ovector.?[1] += 1; //  Advance by one more.
            } else if (self.code.is_utf8) {
                //  Otherwise, ensure we advance a whole UTF-8 character.
                while (self.ovector.?[1] < subject_len) {
                    if ((self.subject[self.ovector.?[1]] & 0xc0) != 0x80) break;
                    self.ovector.?[1] += 1;
                }
            }

            return self.next(); //  Recurse
        }

        //  Other matching errors are not recoverable.
        if (rc < 0) {
            std.log.debug("pcre2zig.MatchIterator.next error: {}", .{rc});
            return error.IteratingMatches;
        }

        // The match succeeded, but the output vector wasn't big enough. This should not happen.
        if (rc == 0) std.log.debug("pcre2zig.MatchIterator.next ovector was not big enough for all the captured substrings.", .{});

        // We must guard against patterns such as /(?=.\K)/ that use \K in an
        // assertion to set the start of a match later than its end. In this
        // demonstration program, we just detect this case and give up. */
        if (self.ovector.?[0] > self.ovector.?[1]) return error.InvalidBackslashK;

        return true;
    }

    pub fn reset(self: *MatchIterator) void {
        //  Run the matching operation from the start.
        _ = pcre2.pcre2_match_8(
            self.code.ptr,
            self.subject.ptr,
            self.subject.len,
            0,
            0,
            self.data.ptr,
            null,
        );

        self.ovector = null;
    }
};

/// Get the captured substring for the given name, if defined.
pub fn namedCapture(code: CompiledCode, data: MatchData, subject: []const u8, name: []const u8) ?[]const u8 {
    return if (code.nameToNumber(name)) |number| numberedCapture(data, subject, number) else null;
}

/// Get the captured substring for the given number, if defined.
pub fn numberedCapture(data: MatchData, subject: []const u8, number: usize) ?[]const u8 {
    const ovector = pcre2.pcre2_get_ovector_pointer_8(data.ptr);
    return subject[ovector[2 * number]..ovector[2 * number + 1]];
}

// Convenience struct for the options used by `replace`.
pub const ReplaceOptions = struct {
    bits: u32 = 0,
    data_opt: ?MatchData = null,
    context_opt_ptr: ?*MatchContext = null,
};

/// Uses the the compiled pattern in `code` to Replace matches in `subject` with `replacement`. Assumes `buf` is
/// large enough to contain the resulting bytes.
pub fn replace(
    code: CompiledCode,
    subject: []const u8,
    start_offset: usize,
    replacement: []const u8,
    buf: []u8,
    options: ReplaceOptions,
) PcreError![]u8 {
    var buf_len = buf.len;
    const num_replacements = pcre2.pcre2_substitute_8(
        code.ptr,
        subject.ptr,
        subject.len,
        start_offset,
        options.bits,
        if (options.data_opt) |data| data.ptr else null,
        if (options.context_opt_ptr) |ptr| ptr else null,
        replacement.ptr,
        replacement.len,
        buf.ptr,
        &buf_len,
    );

    if (num_replacements < 0) {
        std.log.debug("pcre2zig.replace error: {}", .{num_replacements});
        return error.Replacing;
    }

    return buf[0..buf_len];
}

pub const PcreError = error{
    CompilngPattern,
    CopyingCompiledCode,
    CreatingMatchData,
    InvalidBackslashK,
    IteratingMatches,
    Matching,
    Replacing,
};
