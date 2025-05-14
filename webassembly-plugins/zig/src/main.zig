const std = @import("std");
const extism_pdk = @import("extism-pdk");
const Plugin = extism_pdk.Plugin;

const allocator = std.heap.wasm_allocator;

/// This function is called when a client query is received.
/// It takes the client IP address and the query name as parameters.
/// Returns 0 to continue processing the query normally, or -1 to return a REFUSED response.
///
/// Parameters:
/// - client_ip: The client's IP address (without port)
/// - query_name: The domain name being queried
export fn hook_client_query_received() i32 {
    const plugin = Plugin.init(allocator);

    // Parse the JSON input
    const Input = struct {
        client_ip: []const u8,
        query_name: []const u8,
    };

    const input = plugin.getJson(Input) catch |err| {
        const error_msg = std.fmt.allocPrint(allocator, "Failed to parse input JSON: {s}", .{@errorName(err)}) catch unreachable;
        plugin.setError(error_msg);
        allocator.free(error_msg);
        return -1;
    };

    // Log the received query for debugging
    const log_msg = std.fmt.allocPrint(allocator, "Received query from {s} for {s}", .{ input.client_ip, input.query_name }) catch unreachable;
    plugin.log(.Info, log_msg);
    allocator.free(log_msg);

    // Check if the query is for a blocked domain
    const blocked_domains = [_][]const u8{
        "example.com",
        "blocked.example.org",
        "malware.example.net",
    };

    for (blocked_domains) |domain| {
        if (isDomainOrSubdomain(input.query_name, domain)) {
            const block_msg = std.fmt.allocPrint(allocator, "Blocking query for {s} from {s}", .{ input.query_name, input.client_ip }) catch unreachable;
            plugin.log(.Warn, block_msg);
            allocator.free(block_msg);

            // Return -1 to indicate that the query should be refused
            return -1;
        }
    }

    // Return 0 to continue processing the query normally
    return 0;
}

/// Checks if a domain is equal to or a subdomain of another domain.
/// For example, "www.example.com" is a subdomain of "example.com".
fn isDomainOrSubdomain(domain: []const u8, parent: []const u8) bool {
    if (std.mem.eql(u8, domain, parent)) {
        return true;
    }

    // Check if domain ends with ".parent"
    const suffix = std.fmt.allocPrint(allocator, ".{s}", .{parent}) catch return false;
    defer allocator.free(suffix);

    return std.mem.endsWith(u8, domain, suffix);
}
