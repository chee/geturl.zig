const std = @import("std");
const trait = std.meta.trait;
const Allocator = std.mem.Allocator;
const Client = @import("client.zig").Client;
pub const Scope = []const u8;

pub const ApplicationSecret = struct {
    client_id: []const u8 = "",
    client_secret: []const u8 = "",
    token_uri: []const u8 = "",
    auth_uri: []const u8 = "",
    redirect_uris: []const []const u8 = &[_][]const u8{""},
    project_id: ?[]const u8 = null,
    client_email: ?[]const u8 = null,
    auth_provider_x509_cert_url: ?[]const u8 = null,
    client_x509_cert_url: ?[]const u8 = null,
};

pub const InstalledFlowReturnMethod = enum { interactive, http_redirect };

// TODO
pub const InstalledFlowAuth = struct {
    pub fn init(secret: ApplicationSecret, method: InstalledFlowReturnMethod) Authenticator {
        return Authenticator.init(InstalledFlow, InstalledFlow.init(undefined, secret, method));
    }
};

pub const InstalledFlow = struct {
    const Self = @This();
    ptr: *anyopaque,
    secret: ApplicationSecret,
    method: InstalledFlowReturnMethod,
    redirect_uri: fn (*anyopaque) ?[]const u8,
    present_user_url: fn (*anyopaque, []const u8, bool) anyerror![]const u8,

    fn init(ptr: *anyopaque, secret: ApplicationSecret, method: InstalledFlowReturnMethod) Self {
        const Ptr = @TypeOf(ptr);
        const ptr_info = @typeInfo(Ptr);

        if (ptr_info != .Pointer) @compileError("ptr must be a pointer");
        if (ptr_info.Pointer.size != .One) @compileError("ptr must be a single item pointer");

        const alignment = ptr_info.Pointer.alignment;

        const gen = struct {
            fn redirectUri(_: *anyopaque) ?[]const u8 {
                return null;
            }
            fn presentUserUrl(_: *anyopaque, url: []const u8, need_code: bool) ![]const u8 {
                if (need_code) {
                    @panic("todo");
                } else {
                    std.debug.print(
                        \\Please direct your browser to {s} and follow the instructions displayed 
                        \\there.
                        \\
                    , .{url});
                    return "";
                }
            }
            pub fn redirectUriImpl(pointer: *anyopaque) ?[]const u8 {
                const self = @ptrCast(Ptr, @alignCast(alignment, pointer));
                const f = if (@hasDecl(ptr_info.Pointer.child, "redirectUri"))
                    ptr_info.Pointer.child.next
                else
                    @This().redirectUri;

                return @call(.{ .modifier = .always_inline }, f, .{self});
            }
            pub fn presentUserUrlImpl(pointer: *anyopaque, url: []const u8, need_code: bool) anyerror![]const u8 {
                const self = @ptrCast(Ptr, @alignCast(alignment, pointer));
                const f = if (@hasDecl(ptr_info.Pointer.child, "presentUserUrl"))
                    ptr_info.Pointer.child.next
                else
                    @This().presentUserUrl;

                return @call(.{ .modifier = .always_inline }, f, .{ self, url, need_code });
            }
        };

        return .{
            .ptr = ptr,
            .secret = secret,
            .method = method,
            .redirect_uri = gen.redirectUriImpl,
            .present_user_url = gen.presentUserUrlImpl,
        };
    }

    // TODO
    fn token(self: *Self, client: *Client, scopes: []const Scope) !TokenInfo {
        _ = self;
        _ = client;
        _ = scopes;
    }
};

const TokenInfo = struct {
    const Self = @This();
    access_token: []const u8,
    refresh_token: ?[]const u8,
    // TODO: expiration
    id_token: ?[]const u8,

    fn fromJson(allocator: Allocator, json: []const u8) !Self {
        var parser = std.json.Parser.init(allocator, true);
        defer parser.deinit();
        const parsed = try parser.parse(json);
        defer parsed.deinit();
        const obj = parsed.root.Object;

        const token_ty = obj.get("token_type");
        return if (token_ty == null or std.ascii.eqlIgnoreCase(token_ty.?.String, "bearer"))
            return error.InvalidJson
        else
            Self{
                .access_token = obj.get("access_token"),
                .refresh_token = obj.get("refresh_token"),
                .id_token = obj.get("id_token"),
            };
    }
};

// TODO
pub const Authenticator = struct {
    const Self = @This();
    storage: Storage = .memory,
    auth_flow: AuthFlow,

    fn init(comptime T: type, auth: T) Self {
        const auth_flow = if (T == InstalledFlow)
            AuthFlow{ .installed_flow = auth }
        else
            unreachable;
        return Self{ .auth_flow = auth_flow };
    }
};

pub const AuthFlow = union(enum) {
    installed_flow: InstalledFlow,
};

pub const Storage = union(enum) {
    memory,
    disk: []const u8,
};

pub const ScopeHash = struct {
    val: u64,
};

pub const ScopeFilter = struct {
    val: u64,
};

pub const JsonToken = struct {
    scopes: []const Scope,
    token: TokenInfo,
    hash: ScopeHash,
    filter: ScopeFilter,
};

pub const JsonTokens = struct {
    map: std.AutoHashMap(ScopeHash, JsonToken),
};

test "static analysis" {
    std.testing.refAllDecls(@This());
}
