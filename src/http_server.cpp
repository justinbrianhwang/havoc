#include "http_server.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <fstream>
#include <sstream>
#include <iostream>
#include <algorithm>

HttpServer::HttpServer() {}

HttpServer::~HttpServer() {
    stop();
}

std::string HttpRequest::get_query_param(const std::string& key) const {
    size_t pos = 0;
    while (pos < query.size()) {
        size_t eq = query.find('=', pos);
        size_t amp = query.find('&', pos);
        if (amp == std::string::npos) amp = query.size();
        if (eq != std::string::npos && eq < amp) {
            std::string k = query.substr(pos, eq - pos);
            std::string v = query.substr(eq + 1, amp - eq - 1);
            if (k == key) return v;
        }
        pos = amp + 1;
    }
    return "";
}

void HttpServer::route(const std::string& method, const std::string& path, RouteHandler handler) {
    routes_.push_back({method, path, handler});
}

void HttpServer::serve_static(const std::string& url_path, const std::string& file_path, const std::string& content_type) {
    static_files_.push_back({url_path, file_path, content_type});
}

void HttpServer::set_static_dir(const std::string& dir) {
    static_dir_ = dir;
}

bool HttpServer::start(const std::string& host, int port) {
    server_fd_ = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) {
        std::cerr << "[HTTP] Socket creation failed\n";
        return false;
    }

    int opt = 1;
    setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    if (bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        std::cerr << "[HTTP] Bind failed (port " << port << ")\n";
        close(server_fd_);
        return false;
    }

    if (listen(server_fd_, 128) < 0) {
        std::cerr << "[HTTP] Listen failed\n";
        close(server_fd_);
        return false;
    }

    running_ = true;
    accept_thread_ = std::thread(&HttpServer::accept_loop, this);

    std::cout << "[HTTP] Server started: http://" << host << ":" << port << "\n";
    return true;
}

void HttpServer::stop() {
    running_ = false;
    if (server_fd_ >= 0) {
        shutdown(server_fd_, SHUT_RDWR);
        close(server_fd_);
        server_fd_ = -1;
    }
    if (accept_thread_.joinable())
        accept_thread_.join();
}

void HttpServer::accept_loop() {
    while (running_) {
        struct sockaddr_in client_addr{};
        socklen_t len = sizeof(client_addr);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;
        setsockopt(server_fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

        int client_fd = accept(server_fd_, (struct sockaddr*)&client_addr, &len);
        if (client_fd < 0) continue;

        std::thread(&HttpServer::handle_client, this, client_fd).detach();
    }
}

void HttpServer::handle_client(int client_fd) {
    char buf[8192];
    std::string raw;

    struct timeval tv;
    tv.tv_sec = 5;
    tv.tv_usec = 0;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    int n = recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) { close(client_fd); return; }
    buf[n] = '\0';
    raw = buf;

    // If Content-Length exists, receive the full body
    auto cl_pos = raw.find("Content-Length:");
    if (cl_pos != std::string::npos) {
        int content_len = std::stoi(raw.substr(cl_pos + 15));
        auto body_start = raw.find("\r\n\r\n");
        if (body_start != std::string::npos) {
            body_start += 4;
            int body_received = (int)raw.size() - (int)body_start;
            while (body_received < content_len) {
                n = recv(client_fd, buf, std::min((int)sizeof(buf) - 1, content_len - body_received), 0);
                if (n <= 0) break;
                buf[n] = '\0';
                raw += buf;
                body_received += n;
            }
        }
    }

    HttpRequest req = parse_request(raw);
    HttpResponse resp = HttpResponse::not_found();

    // CORS headers (Python client support)
    std::string cors = "Access-Control-Allow-Origin: *\r\n"
                       "Access-Control-Allow-Methods: GET, POST, OPTIONS\r\n"
                       "Access-Control-Allow-Headers: Content-Type\r\n";

    if (req.method == "OPTIONS") {
        std::string r = "HTTP/1.1 204 No Content\r\n" + cors + "\r\n";
        send(client_fd, r.c_str(), r.size(), 0);
        close(client_fd);
        return;
    }

    // API route matching
    for (auto& route : routes_) {
        if (route.method == req.method && route.path == req.path) {
            resp = route.handler(req);
            break;
        }
    }

    // Static file matching
    if (resp.status_code == 404) {
        for (auto& sf : static_files_) {
            if (req.path == sf.url_path) {
                std::string content = read_file(sf.file_path);
                if (!content.empty()) {
                    resp = {200, sf.content_type, content};
                }
                break;
            }
        }
    }

    // Serve files from static_dir
    if (resp.status_code == 404 && !static_dir_.empty()) {
        std::string fpath = static_dir_ + req.path;
        std::string content = read_file(fpath);
        if (!content.empty()) {
            std::string ct = "text/plain";
            if (req.path.find(".html") != std::string::npos) ct = "text/html; charset=utf-8";
            else if (req.path.find(".js") != std::string::npos) ct = "application/javascript";
            else if (req.path.find(".css") != std::string::npos) ct = "text/css";
            else if (req.path.find(".json") != std::string::npos) ct = "application/json";
            resp = {200, ct, content};
        }
    }

    std::string response_str = build_response(resp);
    // Insert CORS
    auto header_end = response_str.find("\r\n");
    if (header_end != std::string::npos) {
        response_str.insert(header_end + 2, cors);
    }

    send(client_fd, response_str.c_str(), response_str.size(), MSG_NOSIGNAL);
    close(client_fd);
}

HttpRequest HttpServer::parse_request(const std::string& raw) {
    HttpRequest req;
    std::istringstream stream(raw);
    std::string line;

    // Request line
    if (std::getline(stream, line)) {
        std::istringstream ls(line);
        std::string path_full;
        ls >> req.method >> path_full;

        auto q = path_full.find('?');
        if (q != std::string::npos) {
            req.path = path_full.substr(0, q);
            req.query = path_full.substr(q + 1);
        } else {
            req.path = path_full;
        }
    }

    // Headers
    while (std::getline(stream, line) && line != "\r" && !line.empty()) {
        if (line.back() == '\r') line.pop_back();
        auto colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = line.substr(0, colon);
            std::string val = line.substr(colon + 1);
            while (!val.empty() && val[0] == ' ') val.erase(0, 1);
            req.headers[key] = val;
        }
    }

    // Body
    auto body_pos = raw.find("\r\n\r\n");
    if (body_pos != std::string::npos) {
        req.body = raw.substr(body_pos + 4);
    }

    return req;
}

std::string HttpServer::build_response(const HttpResponse& resp) {
    std::string status_text;
    switch (resp.status_code) {
        case 200: status_text = "OK"; break;
        case 204: status_text = "No Content"; break;
        case 400: status_text = "Bad Request"; break;
        case 404: status_text = "Not Found"; break;
        default:  status_text = "OK";
    }

    std::ostringstream ss;
    ss << "HTTP/1.1 " << resp.status_code << " " << status_text << "\r\n";
    ss << "Content-Type: " << resp.content_type << "\r\n";
    ss << "Content-Length: " << resp.body.size() << "\r\n";
    ss << "Connection: close\r\n";
    ss << "\r\n";
    ss << resp.body;
    return ss.str();
}

std::string HttpServer::read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f.is_open()) return "";
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}
