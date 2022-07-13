const std = @import("std");
const http = @import("apple_pie");
const trait = std.meta.trait;
const Allocator = std.mem.Allocator;
const Client = @import("main.zig").Client;
const Response = @import("main.zig").Response;
const Headers = @import("main.zig").Headers;
pub const Scope = []const u8;
const server_address = std.net.Address.parseIp("127.0.0.1", 8080) catch unreachable;
const oob_redirect_uri = "urn:ietf:wg:oauth:2.0:oob";
// necessary because of stage1 tuple suckery
// https://github.com/ziglang/zig/issues/7878
const Param = struct { a: []const u8, b: []const u8 };

pub const ApplicationSecret = struct {
    const Self = @This();
    client_id: []const u8,
    client_secret: []const u8,
    token_uri: []const u8,
    auth_uri: []const u8,
    // redirect_uris: []const []const u8,
    project_id: ?[]const u8,
    client_email: ?[]const u8,
    auth_provider_x509_cert_url: ?[]const u8,
    client_x509_cert_url: ?[]const u8,
    _json: std.json.ValueTree,

    pub fn readApplicationSecret(allocator: Allocator, path: []const u8) !Self {
        const file = try std.fs.cwd().readFileAlloc(allocator, path, std.math.maxInt(u32));
        defer allocator.free(file);
        var parser = std.json.Parser.init(allocator, true);
        defer parser.deinit();
        var parsed = try parser.parse(file);
        const root = (parsed.root.Object.get("web") orelse
            parsed.root.Object.get("installed") orelse
            unreachable).Object;
        return Self{
            .client_id = root.get("client_id").?.String,
            .client_secret = root.get("client_secret").?.String,
            .token_uri = root.get("token_uri").?.String,
            .auth_uri = root.get("auth_uri").?.String,
            // .redirect_uris = &[_][]const u8{""},
            .project_id = if (root.get("project_id")) |p| p.String else null,
            .client_email = if (root.get("client_email")) |e| e.String else null,
            .auth_provider_x509_cert_url = if (root.get("auth_provider_x509_cert_url")) |a| a.String else null,
            .client_x509_cert_url = if (root.get("client_x509_cert_url")) |c| c.String else null,
            ._json = parsed,
        };
    }
    pub fn deinit(self: *Self) void {
        self._json.deinit();
    }
};

pub const InstalledFlowReturnMethod = enum { interactive, http_redirect };

// TODO
pub const InstalledFlowAuth = struct {
    pub fn init(allocator: Allocator, client: *Client, secret: ApplicationSecret, method: InstalledFlowReturnMethod) Authenticator {
        return Authenticator.init(InstalledFlow, InstalledFlow.init(undefined, allocator, secret, method), allocator, client);
    }
};

pub const InstalledFlow = struct {
    const Self = @This();
    ptr: *anyopaque,
    allocator: Allocator,
    secret: ApplicationSecret,
    method: InstalledFlowReturnMethod,
    redirect_uri: fn (*anyopaque) ?[]const u8,
    present_user_url: fn (*anyopaque, Allocator, []const u8, bool) anyerror![]const u8,

    fn init(ptr: *anyopaque, allocator: Allocator, secret: ApplicationSecret, method: InstalledFlowReturnMethod) Self {
        const Ptr = @TypeOf(ptr);
        const ptr_info = @typeInfo(Ptr);

        if (ptr_info != .Pointer) @compileError("ptr must be a pointer");
        if (ptr_info.Pointer.size != .One) @compileError("ptr must be a single item pointer");

        const alignment = ptr_info.Pointer.alignment;

        const gen = struct {
            fn redirectUri(_: *anyopaque) ?[]const u8 {
                return null;
            }
            // Caller owned returned slice and must free it.
            fn presentUserUrl(_: *anyopaque, alloc: Allocator, url: []const u8, need_code: bool) ![]const u8 {
                // Show message even when testing
                const writer = if (@import("builtin").is_test)
                    std.io.getStdErr().writer()
                else
                    std.io.getStdOut().writer();
                if (need_code) {
                    try std.fmt.format(writer, "Please direct your browser to {s}, follow the instructions and enter the code displayed here: ", .{url});
                    var list = std.ArrayList(u8).init(alloc);
                    try std.io.getStdIn().reader().readUntilDelimiterArrayList(&list, '\n', std.math.maxInt(u32));
                    return list.toOwnedSlice();
                } else {
                    try std.fmt.format(writer, "Please direct your browser to {s} and follow the instructions displayed there.", .{url});
                    return alloc.dupe(u8, "");
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
            pub fn presentUserUrlImpl(pointer: *anyopaque, alloc: Allocator, url: []const u8, need_code: bool) anyerror![]const u8 {
                const self = @ptrCast(Ptr, @alignCast(alignment, pointer));
                const f = if (@hasDecl(ptr_info.Pointer.child, "presentUserUrl"))
                    ptr_info.Pointer.child.next
                else
                    @This().presentUserUrl;

                return @call(.{ .modifier = .always_inline }, f, .{ self, alloc, url, need_code });
            }
        };

        return .{
            .ptr = ptr,
            .allocator = allocator,
            .secret = secret,
            .method = method,
            .redirect_uri = gen.redirectUriImpl,
            .present_user_url = gen.presentUserUrlImpl,
        };
    }

    fn token(self: *Self, client: *Client, scopes: []const Scope) !TokenInfo {
        return switch (self.method) {
            .http_redirect => try self.askAuthCodeHttp(client, &self.secret, scopes),
            .interactive => try self.askAuthCodeInteractively(client, &self.secret, scopes),
        };
    }
    fn askAuthCodeHttp(self: *const Self, client: *Client, secret: *const ApplicationSecret, scopes: []const []const u8) !TokenInfo {
        var server = InstalledFlowServer.init(self.allocator);
        const redirect_uri = if (self.redirect_uri(self.ptr)) |uri|
            try self.allocator.dupe(u8, uri)
        else blk: {
            var uri = std.ArrayList(u8).init(self.allocator);
            try std.fmt.format(uri.writer(), "http://{}", .{server_address});
            break :blk uri.toOwnedSlice();
        };
        defer self.allocator.free(redirect_uri);
        const url = try buildAuthUrl(self.allocator, secret.auth_uri, secret.client_id, scopes, redirect_uri);
        defer self.allocator.free(url);
        _ = try self.present_user_url(self.ptr, self.allocator, url, false);
        try server.run();
        const auth_code = server.getCode();
        defer self.allocator.free(auth_code);
        return self.exchangeAuthCode(auth_code, client, secret, server_address);
    }
    fn askAuthCodeInteractively(self: *Self, client: *Client, secret: *const ApplicationSecret, scopes: []const []const u8) !TokenInfo {
        const url = try buildAuthUrl(self.allocator, secret.auth_uri, secret.client_id, scopes, self.redirect_uri(self.ptr));
        defer self.allocator.free(url);
        const auth_code = try self.present_user_url(self.ptr, self.allocator, url, true);
        const ret = self.exchangeAuthCode(auth_code, client, secret, null);
        self.allocator.free(auth_code);
        return ret;
    }

    fn exchangeAuthCode(self: *const Self, auth_code: []const u8, client: *Client, secret: *const ApplicationSecret, server_addr: ?std.net.Address) !TokenInfo {
        const redirect_uri = self.redirect_uri(self.ptr);
        var response = try self.requestToken(auth_code, client, secret, redirect_uri, server_addr);
        defer response.deinit();
        return TokenInfo.fromJson(self.allocator, response.body);
    }
    fn requestToken(self: *const Self, auth_code: []const u8, client: *Client, secret: *const ApplicationSecret, maybe_redirect_uri: ?[]const u8, server_addr: ?std.net.Address) !Response {
        const redirect_uri = if (maybe_redirect_uri) |uri|
            try self.allocator.dupe(u8, uri)
        else if (server_addr) |addr|
            try std.fmt.allocPrint(self.allocator, "http://{}", .{addr})
        else
            try self.allocator.dupe(u8, oob_redirect_uri);
        defer self.allocator.free(redirect_uri);
        var body = std.ArrayList(u8).init(self.allocator);
        defer body.deinit();
        const params = [_]Param{
            .{ .a = "code", .b = auth_code },
            .{ .a = "&client_id", .b = secret.client_id },
            .{ .a = "&client_secret", .b = secret.client_secret },
            .{ .a = "&redirect_uri", .b = redirect_uri },
            .{ .a = "&grant_type", .b = "authorization_code" },
        };
        for (params) |param| try std.fmt.format(body.writer(), "{s}={s}", .{ param.a, param.b });
        const headers = .{
            .{ "Content-Type", "application/x-www-form-urlencoded" },
        };
        return client.post(secret.token_uri, .{ .headers = headers, .content = body.items });
    }
};

const InstalledFlowServer = struct {
    const Self = @This();
    allocator: Allocator,
    auth_code: ?[]const u8 = null,
    server: http.Server,

    fn index(ctx: *Self, response: *http.Response, request: http.Request) anyerror!void {
        var uri = try http.Uri.decodeQueryString(ctx.allocator, request.context.uri.query orelse return);
        defer uri.deinit(ctx.allocator);
        var code = uri.get("code") orelse return;
        ctx.auth_code = try ctx.allocator.dupe(u8, code);
        try response.writer().writeAll(
            \\Success
            \\You may now close this window.
        );
        ctx.server.shutdown();
    }

    fn init(allocator: Allocator) Self {
        const server = http.Server.init();
        return Self{ .allocator = allocator, .server = server };
    }

    fn run(self: *Self) !void {
        try self.server.run(
            self.allocator,
            server_address,
            self,
            Self.index,
        );
    }

    fn getCode(self: *const Self) []const u8 {
        while (self.auth_code == null) std.atomic.spinLoopHint();
        return self.auth_code.?;
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
        var parsed = try parser.parse(json);
        defer parsed.deinit();
        const obj = parsed.root.Object;

        const token_ty = obj.get("token_type");
        return if (token_ty == null or !std.ascii.eqlIgnoreCase(token_ty.?.String, "bearer"))
            return error.InvalidJson
        else
            Self{
                .access_token = try allocator.dupe(u8, obj.get("access_token").?.String),
                .refresh_token = if (obj.get("refresh_token")) |t|
                    try allocator.dupe(u8, t.String)
                else
                    null,
                .id_token = if (obj.get("id_token")) |t|
                    try allocator.dupe(u8, t.String)
                else
                    null,
            };
    }

    // TODO
    fn isExpired(_: *const Self) bool {
        return true;
    }

    fn toAccessToken(self: Self) AccessToken {
        return AccessToken{ .value = self.access_token, ._backing = self };
    }
    fn deinit(self: *const Self, allocator: Allocator) void {
        allocator.free(self.access_token);
        if (self.refresh_token) |t| allocator.free(t);
        if (self.id_token) |t| allocator.free(t);
    }
};

// TODO
pub const Authenticator = struct {
    const Self = @This();
    allocator: Allocator,
    storage: Storage,
    auth_flow: AuthFlow,
    client: *Client,

    fn init(comptime T: type, auth: T, allocator: Allocator, client: *Client) Self {
        const storage = Storage{ .memory = .{ .tokens = JsonTokens.init(allocator) } };
        const auth_flow = if (T == InstalledFlow)
            AuthFlow{ .installed_flow = auth }
        else
            unreachable;
        return Self{ .allocator = allocator, .storage = storage, .auth_flow = auth_flow, .client = client };
    }

    pub fn token(self: *Self, scopes: []const []const u8) !AccessToken {
        // TODO: force refresh until expiration is implemented
        const info = try self.findTokenInfo(scopes, .yes);
        return info.toAccessToken();
    }

    pub fn forceRefreshedToken(self: *Self, scopes: []const []const u8) !AccessToken {
        const info = self.findTokenInfo(scopes, .yes);
        return info.toAccessToken();
    }

    pub fn idToken(self: *Self, scopes: []const []const u8) !?[]const u8 {
        const info = self.findTokenInfo(scopes, .yes);
        return info.id_token;
    }

    pub fn findTokenInfo(
        self: *Self,
        scopes: []const []const u8,
        force_refresh: enum { yes, no },
    ) !TokenInfo {
        const hashed_scopes = ScopeSet.from(scopes);
        const tok = self.storage.get(hashed_scopes);
        const app_secret = self.auth_flow.appSecret();
        if (tok) |t| {
            if (!t.isExpired() and force_refresh == .no) return t;
        }
        if (tok != null and tok.?.refresh_token != null and app_secret != null) {
            const token_info = RefreshFlow.refreshToken(self.allocator, self.client, &app_secret.?, tok.?.refresh_token.?) catch
                try self.auth_flow.token(self.client, scopes);
            try self.storage.set(hashed_scopes, token_info);
            return token_info;
        }
        const token_info = try self.auth_flow.token(self.client, scopes);
        try self.storage.set(hashed_scopes, token_info);
        return token_info;
    }
};

const AuthFlow = union(enum) {
    const Self = @This();
    installed_flow: InstalledFlow,

    fn appSecret(self: *Self) ?ApplicationSecret {
        return switch (self.*) {
            .installed_flow => |flow| flow.secret,
        };
    }

    fn token(self: *Self, client: *Client, scopes: []const []const u8) !TokenInfo {
        return switch (self.*) {
            .installed_flow => |*flow| flow.token(client, scopes),
        };
    }
};

pub const Storage = union(enum) {
    const Self = @This();
    memory: struct {
        tokens: JsonTokens,
    },
    disk: struct {
        tokens: JsonTokens,
        path: []const u8,
        fn set(self: *@This(), scopes: ScopeSet, token: TokenInfo) !void {
            _ = self;
            _ = scopes;
            _ = token;
            @panic("todo");
        }
        fn get(self: *@This(), scopes: ScopeSet) ?TokenInfo {
            _ = self;
            _ = scopes;
            @panic("todo");
        }
    },

    pub fn set(self: *Self, scopes: ScopeSet, token: TokenInfo) !void {
        switch (self.*) {
            .memory => |*mem| try mem.tokens.set(scopes, token),
            .disk => |*disk| try disk.set(scopes, token),
        }
    }

    pub fn get(self: *Self, scopes: ScopeSet) ?TokenInfo {
        return switch (self.*) {
            .memory => |*mem| mem.tokens.get(scopes),
            .disk => |*disk| disk.get(scopes),
        };
    }
};

pub const ScopeHash = struct {
    val: u64,
};

pub const ScopeFilter = struct {
    const Self = @This();
    val: u64,

    fn isSubsetOf(self: Self, filter: Self) enum { maybe, no } {
        return if (self.val & filter.val == self.val)
            .maybe
        else
            .no;
    }
};

pub const JsonToken = struct {
    scopes: []const Scope,
    token: TokenInfo,
    hash: ScopeHash,
    filter: ScopeFilter,
};

// TODO
pub const AccessToken = struct {
    value: []const u8,
    // TODO expiration
    _backing: TokenInfo,

    pub fn deinit(self: *const @This(), allocator: Allocator) void {
        self._backing.deinit(allocator);
    }
};

const RefreshFlow = struct {
    fn refreshToken(allocator: Allocator, client: *Client, secret: *const ApplicationSecret, refresh_token: []const u8) !TokenInfo {
        const headers = .{
            .{ "Content-Type", "application/x-www-form-urlencoded" },
        };
        var url = std.ArrayList(u8).init(allocator);
        defer url.deinit();
        try url.appendSlice(secret.token_uri);
        try url.append('&');
        const body = .{
            .{ "client_id", secret.client_id },
            .{ "client_secret", secret.client_secret },
            .{ "refresh_token", refresh_token },
            .{ "grant_type", "refresh_token" },
        };
        inline for (body) |item|
            try std.fmt.format(url.writer(), "{s}={s}", .{ item[0], item[1] });

        var response = try client.post(url.items, headers);
        defer response.deinit();
        var token = try TokenInfo.fromJson(allocator, response.body);
        if (token.refresh_token == null)
            token.refresh_token = refresh_token;

        return token;
    }
};

pub const ScopeSet = struct {
    const Self = @This();
    hash: ScopeHash,
    filter: ScopeFilter,
    scopes: []const []const u8,

    // TODO: scopeset from
    pub fn from(scopes: []const []const u8) Self {
        var hash = ScopeHash{ .val = 0 };
        var filter = ScopeFilter{ .val = 0 };
        for (scopes) |scope| {
            const hashed = std.hash.Wyhash.hash(0, scope);
            for ([_]u6{ 0, 1, 2, 3 }) |i| {
                const h = @truncate(u6, hashed >> (6 * i));
                filter.val |= @as(u64, 1) << h;
            }
            hash.val ^= hashed;
        }

        return Self{
            .hash = hash,
            .filter = filter,
            .scopes = scopes,
        };
    }
};

pub const JsonTokens = struct {
    const Self = @This();
    allocator: Allocator,
    map: std.AutoHashMap(ScopeHash, JsonToken),

    fn init(allocator: Allocator) Self {
        return Self{
            .allocator = allocator,
            .map = std.AutoHashMap(ScopeHash, JsonToken).init(allocator),
        };
    }

    fn get(self: *const Self, scope_set: ScopeSet) ?TokenInfo {
        const hash = scope_set.hash;
        const filter = scope_set.filter;
        const scopes = scope_set.scopes;

        if (self.map.get(hash)) |json_token| return json_token.token;

        var iter = self.map.valueIterator();
        while (iter.next()) |val| {
            if (filter.isSubsetOf(val.filter) != .maybe) break;
            const other_scopes = val.scopes;
            const is_subset_of = blk: {
                var all = true;
                for (scopes) |s| {
                    var any = false;
                    for (other_scopes) |t| t: {
                        any = std.mem.eql(u8, t, s);
                        if (any) break :t;
                    }
                    all = any;
                    if (!all) break :blk all;
                }
                break :blk all;
            };
            if (is_subset_of) {
                return val.token;
            }
        }
        return null;
    }
    fn set(self: *Self, scope_set: ScopeSet, token: TokenInfo) !void {
        const hash = scope_set.hash;
        const filter = scope_set.filter;
        const scopes = scope_set.scopes;

        if (self.map.get(hash)) |*e| {
            e.token = token;
        } else {
            const json_token = JsonToken{
                .scopes = scopes,
                .token = token,
                .hash = hash,
                .filter = filter,
            };
            try self.map.put(hash, json_token);
        }
    }

    fn deinit(self: *Self) void {
        var iter = self.map.iterator();
        while (iter.next()) |item| {
            _ = item;
        }
        self.map.deinit();
    }
};

fn buildAuthUrl(allocator: Allocator, auth_uri: []const u8, client_id: []const u8, scopes: []const []const u8, redirect_uri: ?[]const u8) ![]const u8 {
    var url = std.ArrayList(u8).init(allocator);
    try url.appendSlice(auth_uri);
    if (url.items[url.items.len - 1] != '?' or
        std.mem.indexOfScalar(u8, url.items, '?') == null)
    {
        try url.append('?');
    }
    const scopes_string = try std.mem.join(allocator, " ", scopes);
    defer allocator.free(scopes_string);
    const params = [_]Param{
        .{ .a = "scope", .b = scopes_string },
        .{ .a = "&access_type", .b = "offline" },
        .{ .a = "&redirect_uri", .b = redirect_uri orelse oob_redirect_uri },
        .{ .a = "&response_type", .b = "code" },
        .{ .a = "&client_id", .b = client_id },
    };
    for (params) |param| try std.fmt.format(url.writer(), "{s}={s}", .{ param.a, param.b });
    var haystack = url.items;
    while (std.mem.indexOfScalar(u8, haystack, ' ')) |begin| {
        const real_first = begin + (@ptrToInt(haystack.ptr) - @ptrToInt(url.items.ptr));
        try url.replaceRange(real_first, 1, "%20");
        haystack = url.items[real_first + 3 ..];
    }
    return url.toOwnedSlice();
}

test "static analysis" {
    std.testing.refAllDecls(@This());
}
