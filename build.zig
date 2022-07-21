const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{});

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("geturl", "src/main.zig");

    exe.addPackagePath("getseq", "vendor/getseq/src/main.zig");
    exe.addPackagePath("requestz", "vendor/requestz/src/main.zig");
    exe.addPackagePath("mimetypes", "vendor/mimetypes/src/mimetypes.zig");

    exe.addIncludePath("vendor/pcre/libs/pcre2-10.39/src");
    exe.addLibraryPath("vendor/pcre/zig-out/lib");
    exe.linkSystemLibraryName("pcre2zig");
    exe.addPackagePath("pcre", "vendor/pcre/src/pcre2zig.zig");

    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
}