#pragma once
#include <string>
#include <functional>
#include <map>
#include <thread>
#include <atomic>

struct HttpRequest {
    std::string method;   // GET, POST
    std::string path;     // /api/attacks
    std::string query;    // key=value&...
    std::string body;
    std::map<std::string, std::string> headers;

    std::string get_query_param(const std::string& key) const;
};

struct HttpResponse {
    int status_code = 200;
    std::string content_type = "application/json";
    std::string body;

    static HttpResponse json(const std::string& j)  { return {200, "application/json; charset=utf-8", j}; }
    static HttpResponse html(const std::string& h)   { return {200, "text/html; charset=utf-8", h}; }
    static HttpResponse text(const std::string& t)    { return {200, "text/plain; charset=utf-8", t}; }
    static HttpResponse not_found()                   { return {404, "text/plain", "404 Not Found"}; }
    static HttpResponse error(const std::string& msg) { return {400, "application/json", "{\"error\":\"" + msg + "\"}"}; }
};

using RouteHandler = std::function<HttpResponse(const HttpRequest&)>;

class HttpServer {
public:
    HttpServer();
    ~HttpServer();

    void route(const std::string& method, const std::string& path, RouteHandler handler);
    void serve_static(const std::string& url_path, const std::string& file_path, const std::string& content_type);
    void set_static_dir(const std::string& dir);

    bool start(const std::string& host, int port);
    void stop();
    bool is_running() const { return running_; }

private:
    void accept_loop();
    void handle_client(int client_fd);
    HttpRequest parse_request(const std::string& raw);
    std::string build_response(const HttpResponse& resp);
    std::string read_file(const std::string& path);

    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::thread accept_thread_;
    std::string static_dir_;

    struct Route {
        std::string method;
        std::string path;
        RouteHandler handler;
    };
    std::vector<Route> routes_;

    struct StaticFile {
        std::string url_path;
        std::string file_path;
        std::string content_type;
    };
    std::vector<StaticFile> static_files_;
};
