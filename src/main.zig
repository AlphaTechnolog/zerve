const std = @import("std");
const mime = @import("./mime.zig");

const posix = std.posix;
const math = std.math;
const net = std.net;
const mem = std.mem;
const ascii = std.ascii;
const json = std.json;
const io = std.io;
const fs = std.fs;
const fmt = std.fmt;

const StringHashMap = std.StringHashMap;
const ArrayList = std.ArrayList;

const Server = net.Server;
const Address = net.Address;

const Allocator = mem.Allocator;

const Request = struct {
    // internal request data such as low level structures.
    allocator: Allocator,
    connection: Server.Connection,

    // incoming request parsed data.
    url: ?[]const u8 = null,
    method: ?Method = null,
    headers: ?StringHashMap([]const u8) = null,
    body: ?[]const u8 = null,

    pub const Method = enum {
        GET,
        POST,
        PUT,
        DELETE,
        HEAD,
        OPTIONS,
        CONNECT,
        TRACE,
        PATCH,

        pub fn fromString(input: []const u8) ?Method {
            var lower_input_buf: [256]u8 = undefined;
            const lower_input = ascii.lowerString(&lower_input_buf, input);

            if (mem.eql(u8, lower_input, "get")) return .GET;
            if (mem.eql(u8, lower_input, "post")) return .POST;
            if (mem.eql(u8, lower_input, "put")) return .PUT;
            if (mem.eql(u8, lower_input, "delete")) return .DELETE;
            if (mem.eql(u8, lower_input, "head")) return .HEAD;
            if (mem.eql(u8, lower_input, "options")) return .OPTIONS;
            if (mem.eql(u8, lower_input, "connect")) return .CONNECT;
            if (mem.eql(u8, lower_input, "trace")) return .TRACE;
            if (mem.eql(u8, lower_input, "patch")) return .PATCH;

            return null;
        }
    };

    pub fn init(allocator: Allocator, connection: Server.Connection) Request {
        return Request{
            .allocator = allocator,
            .connection = connection,
        };
    }

    pub fn read(self: Request) ![]u8 {
        var recv_buffer: [4096]u8 = undefined;
        var recv_total: usize = 0;

        while (@as(?usize, try self.connection.stream.read(recv_buffer[recv_total..]))) |recv_len| {
            if (recv_len == 0) break;
            recv_total += recv_len;
            const haystack = recv_buffer[0..recv_total];
            if (mem.containsAtLeast(u8, haystack, 1, "\r\n\r\n")) {
                break;
            }
        }

        return try self.allocator.dupe(u8, recv_buffer[0..recv_total]);
    }

    pub fn parseRequest(self: *Request) !void {
        const contents = try self.read();
        defer self.allocator.free(contents);

        var contents_it = mem.tokenizeAny(u8, contents, "\n");

        if (contents_it.next()) |first_line| {
            var it = mem.tokenizeAny(u8, first_line, " ");
            self.method = Method.fromString(it.next() orelse return);
            self.url = try self.allocator.dupe(u8, it.next() orelse return);
        }

        self.headers = StringHashMap([]const u8).init(self.allocator);

        while (contents_it.next()) |line| {
            if (!mem.containsAtLeast(u8, line, 1, ": ")) {
                // this is the indicator that we should stop here, and maybe in the next line
                // we have a body or not (who knows, just an if can).
                break;
            }

            var it = mem.tokenizeAny(u8, line, ": ");

            const key = try self.allocator.dupe(u8, it.next() orelse continue);
            const value = try self.allocator.dupe(u8, it.next() orelse continue);

            if (self.headers) |*headers| {
                try headers.put(key, value);
            }
        }

        if (contents_it.next()) |body| {
            self.body = try self.allocator.dupe(u8, body);
        }
    }

    pub fn respond(self: *Request, response: *Response) !void {
        const http_response = try response.toHTTP();

        defer {
            self.connection.stream.close();
            self.allocator.free(http_response);
        }

        _ = try self.connection.stream.write(http_response);
    }

    pub fn deinit(self: *Request) void {
        if (self.url) |url| self.allocator.free(url);
        if (self.body) |body| self.allocator.free(body);
        if (self.headers) |*headers| {
            var keys = headers.keyIterator();
            while (keys.next()) |key| {
                if (headers.get(key.*)) |value| {
                    self.allocator.free(value);
                }
                self.allocator.free(key.*);
            }
            headers.deinit();
        }
    }
};

const Response = struct {
    allocator: Allocator,
    statuscode: i16 = 200,
    headers: ?StringHashMap([]const u8) = null,
    contents: ?[]const u8 = null,

    pub fn fromJSON(json_value: anytype, opts: struct {
        allocator: Allocator,
        statuscode: i16 = 200,
        headers: ?StringHashMap([]const u8) = null,
    }) !Response {
        var string = ArrayList(u8).init(opts.allocator);
        try json.stringify(json_value, .{}, string.writer());

        return Response{
            .allocator = opts.allocator,
            .statuscode = opts.statuscode,
            .contents = try string.toOwnedSlice(),
            .headers = opts.headers orelse headers: {
                var headers = StringHashMap([]const u8).init(opts.allocator);
                try headers.put("Content-Type", "application/json");
                break :headers headers;
            },
        };
    }

    pub fn toHTTP(self: *Response) ![]const u8 {
        var response = ArrayList(u8).init(self.allocator);

        const writer = response.writer();

        try writer.print("HTTP/1.1 {d} OK\r\n", .{self.statuscode});

        if (self.headers) |*headers| {
            var keys = headers.keyIterator();
            while (keys.next()) |key| {
                if (headers.get(key.*)) |value| {
                    try writer.print("{s}: {s}\r\n", .{ key.*, value });
                }
            }
        }

        if (self.contents) |contents| {
            try writer.print("Content-Length: {d}\r\n", .{contents.len});
            try writer.print("\r\n{s}", .{contents});
        }

        // free any remaining memory out there, anyways they all should be already copied
        // into the response buffer.
        self.deinit();

        return try response.toOwnedSlice();
    }

    pub fn deinit(self: *Response) void {
        if (self.contents) |value| self.allocator.free(value);
        if (self.headers) |*headers| headers.deinit();
    }
};

const FileServer = struct {
    allocator: Allocator,
    request: Request,

    pub fn init(allocator: Allocator, request: Request) FileServer {
        return FileServer{
            .allocator = allocator,
            .request = request,
        };
    }

    pub const ProcessError = anyerror || error{
        InvalidRequest,
    };

    fn serveFile(self: FileServer, url: []const u8) !Response {
        var dotit = mem.tokenizeAny(u8, url, ".");
        var ext: []const u8 = undefined;

        while (dotit.next()) |v| {
            ext = v;
        }

        var buf: [256]u8 = undefined;

        const file_ext = try fmt.bufPrint(&buf, "{s}", .{ext});
        const mimetype = mime.extension_map.get(file_ext) orelse .@"application/octet-stream";

        var headers = StringHashMap([]const u8).init(self.allocator);
        try headers.put("Content-Type", @tagName(mimetype));

        const file = fs.cwd().openFile(url[1..], .{}) catch |err| {
            return Response.fromJSON(.{ .errcode = @errorName(err) }, .{
                .allocator = self.allocator,
            });
        };

        defer file.close();

        return Response{
            .allocator = self.allocator,
            .statuscode = 200,
            .headers = headers,
            .contents = contents: {
                var content_array = ArrayList(u8).init(self.allocator);
                try file.reader().readAllArrayList(&content_array, math.maxInt(u32));
                break :contents try content_array.toOwnedSlice();
            },
        };
    }

    fn serveFolder(self: FileServer, url: []const u8) !Response {
        var html = ArrayList(u8).init(self.allocator);
        var bw = io.bufferedWriter(html.writer());

        const writer = bw.writer();

        try writer.print("<!doctype html><html><body><ul>\n", .{});

        var path_buf: [256]u8 = undefined;
        const path = try fmt.bufPrint(&path_buf, ".{s}", .{url});

        var folder = fs.cwd().openDir(path, .{ .iterate = false, .access_sub_paths = false }) catch |err| {
            return Response.fromJSON(.{ .errcode = @errorName(err) }, .{
                .allocator = self.allocator,
            });
        };

        defer folder.close();

        var it = folder.iterate();

        try writer.print("<li><a href=\"{s}{s}../\">DIR  ..</a></li>", .{
            url,
            if (mem.endsWith(u8, url, "/")) "" else "/",
        });

        while (try it.next()) |entry| {
            const prefix = switch (entry.kind) {
                .directory => "DIR ",
                .file => "FILE",
                else => "ANY ",
            };

            var href_buf: [512]u8 = undefined;

            const href = try fmt.bufPrint(&href_buf, "{s}{s}{s}", .{
                url,
                // complete with / only if needed.
                if (mem.endsWith(u8, url, "/")) "" else "/",
                entry.name,
            });

            try writer.print("<li><a href=\"{s}\">{s} {s}</a></li>\n", .{
                href,
                prefix,
                entry.name,
            });
        }

        try writer.print("</ul></body>\n", .{});

        return Response{
            .allocator = self.allocator,
            .statuscode = 200,
            .contents = contents: {
                try bw.flush();
                break :contents try html.toOwnedSlice();
            },
        };
    }

    pub fn process(self: FileServer) ProcessError!Response {
        const url = self.request.url orelse return error.InvalidRequest;
        const method = self.request.method orelse return error.InvalidRequest;

        // TODO: Maybe allow files uploads
        if (method != .GET) {
            return Response.fromJSON(.{ .err = "Method not allowed" }, .{
                .allocator = self.allocator,
                .statuscode = 405,
            });
        }

        const RequestResource = enum {
            dir,
            file,

            pub fn fromUrl(value: []const u8) @This() {
                const stat = fs.cwd().statFile(value[1..]) catch return .dir;

                // maybe check for other stat outcomes.
                return switch (stat.kind) {
                    .directory => .dir,
                    else => .file,
                };
            }
        };

        const resource = RequestResource.fromUrl(url);
        const stdout = io.getStdOut().writer();

        try stdout.print("{s} - {s}: {s}\n", .{
            @tagName(method),
            @tagName(resource),
            url,
        });

        switch (RequestResource.fromUrl(url)) {
            .dir => return try self.serveFolder(url),
            .file => return try self.serveFile(url),
        }
    }
};

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    defer if (gpa.deinit() == .leak) {
        std.debug.print("memleak detected!\n", .{});
    };

    const allocator = gpa.allocator();
    const address = try Address.resolveIp("0.0.0.0", 8000);

    var listener = address.listen(.{ .reuse_address = true }) catch |err| {
        std.debug.panic("Unable to listen at port 8000: {s}\n", .{@errorName(err)});
        std.posix.exit(1);
        unreachable;
    };

    try stdout.print("Server is listening at port 8000\n", .{});

    while (true) {
        const connection = listener.accept() catch |err| {
            try stderr.print("Unable to accept request: {s}\n", .{@errorName(err)});
            continue;
        };

        var request = Request.init(allocator, connection);
        defer request.deinit();

        request.parseRequest() catch |err| {
            try stderr.print("FATAL: Unable to parse request: {s}\n", .{@errorName(err)});
            std.posix.exit(1);
            return;
        };

        const file_server = FileServer.init(allocator, request);
        var response = try file_server.process();

        request.respond(&response) catch |err| {
            try stderr.print("FATAL: Unable to respond to request: {s}\n", .{@errorName(err)});
            std.posix.exit(1);
            return;
        };
    }
}
