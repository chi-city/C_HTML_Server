#define _POSIX_C_SOURCE 200809L
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/select.h>
#include <assert.h>

#include <sys/socket.h>
#include <arpa/inet.h>

#define exit(N)         \
    {                   \
        fflush(stdout); \
        fflush(stderr); \
        _exit(N);       \
    }

// TODO: REDO TESTS 9-10, and finish.

static const char ping_request[] = "GET /ping HTTP/1.1\r\n\r\n";
static const char echo_request[] = "GET /echo HTTP/1.1\r\n";
static const char write_request[] = "POST /write HTTP/1.1\r\n";
static const char read_request[] = "GET /read HTTP/1.1\r\n";
static const char file_request[] = "GET /%s HTTP/1.1\r\n";
static const char stats_request[] = "GET /stats HTTP/1.1\r\n";

static const char stats_response_body[] = "Requests: %d\nHeader bytes: %d\nBody bytes: %d\nErrors: %d\nError bytes: %d";

static const char OK200_response[] = "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n";
static const char err404_response[] = "HTTP/1.1 404 Not Found";
static const char err400_response[] = "HTTP/1.1 400 Bad Request";

static const char content_len_header[] = "Content-Length: %d";

static char written[1024] = "<empty>";
static int written_size = 7;

static const char ping_header[] = "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\n";
static const char ping_body[] = "pong";

static char request[2048];

static char head[1024];
static int head_size = 0;
static char body[1024];
static int body_size = 0;

static int reqs = 0;
static int head_bytes = 0;
static int body_bytes = 0;
static int errs = 0;
static int err_bytes = 0;

static fd_set read_set;
static fd_set write_set;

static int client_sockets[8];
static int client_fds[8];
static int client_sizes[8];

static int get_port();
static int prep_socket(int port);
static int accept_client(int server_socket);
static void send_response(int client_socket);
static void send_error(int client_socket, const char *error);
static void handle_requests(int client_socket);
static void handle_ping(int client_socket);
static void handle_echo(int client_socket);
static void handle_write(int client_socket);
static void handle_read(int client_socket);
static void handle_file(int client_socket);
static void handle_stats(int client_socket);
static void handle_ready_to_write(int idx);

int main(int argc, char **argv)
{
    int port = get_port();

    printf("Using port %d\n", port);
    printf("PID: %d\n", getpid());

    // Create server socket
    int server_socket = prep_socket(port);

    // Process client requests
    while (1)
    {
        int client_socket = accept_client(server_socket);

        handle_requests(client_socket);
    }

    return 0;
}

static int get_port()
{
    int fd = open("port.txt", O_RDONLY);
    if (fd < 0)
    {
        perror("Could not open port");
        exit(1);
    }

    char buffer[32];
    int r = read(fd, buffer, sizeof(buffer));
    if (r < 0)
    {
        perror("Could not read port");
        exit(1);
    }

    return atoi(buffer);
}

static int prep_socket(int port)
{
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1)
    {
        perror("Could not create socket");
        exit(1);
    }

    // Bind Socket to the address
    struct sockaddr_in address = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = INADDR_ANY,
        .sin_port = htons(port)};
    inet_pton(AF_INET, "127.0.0.1", &(address.sin_addr));
    int optval = 1;
    setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

    if (bind(server_socket, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        perror("Could not bind socket to address");
        exit(1);
    }

    // Listen for incoming connections
    if (listen(server_socket, 10) < 0)
    {
        perror("Could not listen for connections");
        exit(1);
    }

    return server_socket;
}

static void handle_ready_to_write(int idx)
{
    int client_socket = client_sockets[idx];
    int fd = client_fds[idx];
    assert(client_socket != 0);
    assert(fd != 0);

    int file_read = read(fd, body, sizeof(body));
    int file_sent = send(client_socket, body, file_read, 0);

    while (file_sent != file_read)
    {
        file_sent += send(client_socket, body + file_sent, file_read - file_sent, 0);
    }
    assert(file_sent == file_read);

    body_bytes += file_sent;

    client_sizes[idx] -= file_sent;

    if (client_sizes[idx] == 0) {
        reqs += 1;
        close(fd);
        close(client_socket);
        client_sockets[idx] = 0;
        client_fds[idx] = 0;
    }
}

static int accept_client(int server_socket)
{
    static struct sockaddr_in client;
    static socklen_t client_size;

    int client_socket = 0;
    while (client_socket == 0)
    {
        FD_ZERO(&read_set);
        FD_ZERO(&write_set);

        int max = server_socket;
        for (int i = 0; i < 8; i++) {
            if (client_sockets[i] != 0) {
                FD_SET(client_sockets[i], &write_set);
                if (client_sockets[i] > max) {
                    max = client_sockets[i];
                }
            }
        }

        FD_SET(server_socket, &read_set);

        int ready = select(max+1, &read_set, &write_set, NULL, NULL);
        if (ready < 0)
        {
            perror("Error on select");
            exit(1);
        }

        for (int i = 0; ready != 0 && i < 8; i++) {
            if (FD_ISSET(client_sockets[i], &write_set)) {
                handle_ready_to_write(i);
                ready -= 1;
            }
        }

        if (ready != 0 && FD_ISSET(server_socket, &read_set))
        {
            client_socket = accept(server_socket, (struct sockaddr *)&client, &client_size);
            if (client_socket < 0)
            {
                perror("Could not accept incoming connection");
                exit(1);
            }
        }
    }

    return client_socket;
}

static void send_response(int client_socket)
{
    int head_sent = send(client_socket, head, head_size, 0);
    int body_sent = 0;

    while (body_sent != body_size)
    {
        body_sent += send(client_socket, body + body_sent, body_size - body_sent, 0);
    }

    assert(head_sent == head_size);
    assert(body_sent == body_size);

    reqs += 1;
    head_bytes += head_size;
    body_bytes += body_size;
}

static void send_error(int client_socket, const char *error)
{
    int len = strlen(error);
    int sent = send(client_socket, error, len, 0);
    assert(sent == len);

    errs += 1;
    err_bytes += len;
}

static void handle_echo(int client_socket)
{
    char *end = strstr(request, "\r\n\r\n");
    if (end == NULL)
    {
        end = request + 1024;
    }

    *end = '\0';

    char *start = strstr(request, "\r\n");
    assert(start != NULL);

    start += 2;

    body_size = strlen(start);
    memcpy(body, start, body_size);

    head_size = snprintf(head, sizeof(head), OK200_response, body_size);
    send_response(client_socket);
}

static void handle_write(int client_socket)
{
    char *start = strstr(request, "\r\n\r\n");
    assert(start != NULL);
    start += 4;

    char *tok = strtok(request, "\r\n");
    assert(tok != NULL);
    tok = strtok(NULL, "\r\n");

    int length = 0;
    while (tok != NULL)
    {
        if (sscanf(tok, content_len_header, &length) != 0)
        {
            break;
        }
        tok = strtok(NULL, "\r\n");
    }

    assert(length != 0);

    if (length > 1024)
    {
        length = 1024;
    }

    written_size = length;
    memcpy(written, start, written_size);

    handle_read(client_socket);
}

static void handle_read(int client_socket)
{
    body_size = written_size;
    memcpy(body, written, body_size);

    head_size = snprintf(head, sizeof(head), OK200_response, body_size);
    send_response(client_socket);
}

static void handle_ping(int client_socket)
{
    head_size = strlen(ping_header);
    memcpy(head, ping_header, head_size);

    body_size = strlen(ping_body);
    memcpy(body, ping_body, body_size);
    send_response(client_socket);
}

static void handle_file(int client_socket)
{
    static char path[128];
    int found = sscanf(request, file_request, path);
    assert(found > 0);

    int fd = open(path, O_RDONLY);
    if (fd < 0)
    {
        send_error(client_socket, err404_response);
        close(client_socket);
        return;
    }

    struct stat s;
    fstat(fd, &s);

    int file_size = s.st_size;

    head_size = snprintf(head, sizeof(head), OK200_response, file_size);
    int sent = send(client_socket, head, head_size, 0);

    assert(sent == head_size);

    head_bytes += head_size;

    int idx = -1;
    for (int i = 0; i < 8; i++)
    {
        if (client_sockets[i] == 0)
        {
            idx = i;
            break;
        }
    }
    assert(idx != -1);

    client_sockets[idx] = client_socket;
    client_fds[idx] = fd;
    client_sizes[idx] = file_size;
}

static void handle_stats(int client_socket)
{
    body_size = snprintf(body, sizeof(body), stats_response_body, reqs, head_bytes, body_bytes, errs, err_bytes);
    head_size = snprintf(head, sizeof(head), OK200_response, body_size);
    send_response(client_socket);
}

void handle_requests(int client_socket)
{
    if (recv(client_socket, request, sizeof(request), 0) == 0)
    {
        return;
    }

    if (!strncmp(request, ping_request, strlen(ping_request)))
    { // Test 2
        handle_ping(client_socket);
        close(client_socket);
        return;
    }
    else if (!strncmp(request, echo_request, strlen(echo_request)))
    { // Test 3
        handle_echo(client_socket);
        close(client_socket);
        return;
    }
    else if (!strncmp(request, write_request, strlen(write_request)))
    { // Test 4
        handle_write(client_socket);
        close(client_socket);
        return;
    }
    else if (!strncmp(request, read_request, strlen(read_request)))
    { // Test 4
        handle_read(client_socket);
        close(client_socket);
        return;
    }
    else if (!strncmp(request, stats_request, strlen(stats_request)))
    { // Test  8 
        handle_stats(client_socket);
        close(client_socket);
        return;
    }
    else if (!strncmp(request, "GET ", 4))
    { // Test 5
        handle_file(client_socket);
        return;
    }
    else
    {
        send_error(client_socket, err400_response);
        close(client_socket);
        return;
    }
}
