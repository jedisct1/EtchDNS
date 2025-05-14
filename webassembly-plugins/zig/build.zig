const std = @import("std");

pub fn build(b: *std.Build) void {
    const optimize = b.standardOptimizeOption(.{});
    const target = b.standardTargetOptions(.{
        .default_target = .{ .abi = .musl, .os_tag = .freestanding, .cpu_arch = .wasm32 },
    });

    // Create a module for the extism-pdk dependency
    const pdk_dep = b.dependency("extism-pdk", .{
        .target = target,
        .optimize = optimize,
    });
    const pdk_module = pdk_dep.module("extism-pdk");

    // Create the plugin executable
    var plugin = b.addExecutable(.{
        .name = "etchdns-plugin",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    plugin.rdynamic = true;
    plugin.entry = .disabled;
    plugin.root_module.addImport("extism-pdk", pdk_module);

    b.installArtifact(plugin);
    const plugin_step = b.step("etchdns-plugin", "Build etchdns-plugin");
    plugin_step.dependOn(b.getInstallStep());
}
