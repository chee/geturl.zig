const std = @import("std");

const pcre2_cfiles = &[_][]const u8{
    "libs/pcre2-10.39/src/pcre2_auto_possess.c",
    "libs/pcre2-10.39/src/pcre2_chartables.c",
    "libs/pcre2-10.39/src/pcre2_compile.c",
    "libs/pcre2-10.39/src/pcre2_config.c",
    "libs/pcre2-10.39/src/pcre2_context.c",
    "libs/pcre2-10.39/src/pcre2_convert.c",
    "libs/pcre2-10.39/src/pcre2_dfa_match.c",
    "libs/pcre2-10.39/src/pcre2_error.c",
    "libs/pcre2-10.39/src/pcre2_extuni.c",
    "libs/pcre2-10.39/src/pcre2_find_bracket.c",
    "libs/pcre2-10.39/src/pcre2_jit_compile.c",
    "libs/pcre2-10.39/src/pcre2_maketables.c",
    "libs/pcre2-10.39/src/pcre2_match.c",
    "libs/pcre2-10.39/src/pcre2_match_data.c",
    "libs/pcre2-10.39/src/pcre2_newline.c",
    "libs/pcre2-10.39/src/pcre2_ord2utf.c",
    "libs/pcre2-10.39/src/pcre2_pattern_info.c",
    "libs/pcre2-10.39/src/pcre2_script_run.c",
    "libs/pcre2-10.39/src/pcre2_serialize.c",
    "libs/pcre2-10.39/src/pcre2_string_utils.c",
    "libs/pcre2-10.39/src/pcre2_study.c",
    "libs/pcre2-10.39/src/pcre2_substitute.c",
    "libs/pcre2-10.39/src/pcre2_substring.c",
    "libs/pcre2-10.39/src/pcre2_tables.c",
    "libs/pcre2-10.39/src/pcre2_ucd.c",
    "libs/pcre2-10.39/src/pcre2_valid_utf.c",
    "libs/pcre2-10.39/src/pcre2_xclass.c",
};
const pcre2_cflags = &[_][]const u8{
    "-D",
    "PCRE2_CODE_UNIT_WIDTH=8",
    "-D",
    "HAVE_CONFIG_H",
    "-I",
    "libs/pcre2-10.39/src",
};

pub fn build(b: *std.build.Builder) void {
    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("pcre2zig", "src/main.zig");
    lib.setBuildMode(mode);
    lib.linkLibC();
    lib.addIncludePath("libs/pcre2-10.39/src");
    lib.addCSourceFiles(pcre2_cfiles, pcre2_cflags);
    lib.install();

    const main_tests = b.addTest("src/main.zig");
    main_tests.setBuildMode(mode);
    main_tests.linkLibC();
    main_tests.addIncludePath("libs/pcre2-10.39/src");
    main_tests.addCSourceFiles(pcre2_cfiles, pcre2_cflags);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}
