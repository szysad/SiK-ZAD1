#include <stdio.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <regex.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>

#define MUL_AND_DIV(NUMB, MUL, DIV) ((NUMB / DIV) * MUL)
#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define RET_ERR(RET_CODE, MSG) { set_err(MSG); return (RET_CODE); }

#define BUFFER_SIZE 8192
#define ERR_MSG_SIZE 64
#define ARGS 4
#define SYNTAX_ERR -5
#define LINE_PROC_FUN 3
#define NO_MATCH 0
#define MATCH 420
#define NOT_READ_ENOUGHT 69
#define SYSTEM_ERR -12
#define END_OF_HEADER 15

#define SP ' '
#define HTAB '\t'
#define NL '\n'
#define CRLF "\r\n"
#define OWS_CHARSET "\t "

static char ERR_MSG[ERR_MSG_SIZE];

struct raport {
    int64_t real_content_len;
    char *cookies_exposition;
};

struct header_d {
    bool chunk_transfer;
    bool content_length_found;
    bool chunk_transfer_found;
    uint64_t content_length;
    char *set_cookie;
};

typedef int (*proc_header_f)(char buffer[BUFFER_SIZE], struct header_d *data, int line_start, int line_end);

void raport_print(struct raport raport) {
    printf("Dlugosc zasobu: %ld\n", raport.real_content_len);
    if (raport.cookies_exposition)
        printf("%s\n", raport.cookies_exposition);
}

void raport_free(struct raport raport) {
    free(raport.cookies_exposition);
}

void set_err(char *msg) {
    int len = MIN(strlen(msg), ERR_MSG_SIZE - 1);
    strncpy(ERR_MSG, msg, len);
    ERR_MSG[len] = 0;
}

void print_err() { fprintf(stderr, "ERROR: %s\n", ERR_MSG); }

void header_d_init(struct header_d* data) { // DEBUG
    data->chunk_transfer_found = false;
    data->content_length_found = false;
    data->set_cookie = NULL;
}

int header_d_invalid(struct header_d* data) {
    int trues = data->chunk_transfer_found + data->content_length_found;
    return (trues % 2 == 0);
}
 
int add_cookie(struct header_d *data, char buffer[BUFFER_SIZE], int start, int len) {
    if (data->set_cookie == NULL) {
        data->set_cookie = malloc(len + 1);
        if (data->set_cookie == NULL) RET_ERR(-1, "memory allocation fail");
        strncpy(data->set_cookie, buffer + start, len);
        memset(data->set_cookie + len, 0, 1);
        return 0;
    }
    int prev_len = strlen(data->set_cookie); 
    char *newstrn = malloc(prev_len + len + 2);
    if (newstrn == NULL) RET_ERR(-1, "memory allocation fail");

    strncpy(newstrn, data->set_cookie, prev_len);
    memset(newstrn + prev_len, NL, 1);
    strncpy(newstrn + prev_len + 1, buffer + start, len);
    memset(newstrn + prev_len + len + 1, 0, 1);

    free(data->set_cookie);
    data->set_cookie = newstrn;
    return 0;
}

int skip_chars(char buffer[BUFFER_SIZE], char* chars, int *start, int end) {
    int i = *start;
    bool skips = (strchr(chars, buffer[i]) != NULL);
    while (i < end && skips) {
        i++;
        skips = (strchr(chars, buffer[i]) != NULL);
    }
    if (skips) return 1;
    *start = i;
    return 0;
}

int proc_content_length_f(char buffer[BUFFER_SIZE], struct header_d *data, int l_s, int l_e) {
    char *pref = "Content-Length:";
    int pref_len = strlen(pref);
    if (strncasecmp(buffer + l_s, pref, pref_len)) return NO_MATCH;
    int i = pref_len + l_s;
    if (skip_chars(buffer, OWS_CHARSET, &i, l_e)) RET_ERR(SYSTEM_ERR, "wrong header Content-Length field syntax");
    if (data->content_length_found) RET_ERR(SYNTAX_ERR, "multpile Contelnt-Length header fields");
    data->content_length_found = true;
    errno = 0;
    data->content_length = strtoll(buffer + i, NULL, 10);
    if (errno) RET_ERR(SYNTAX_ERR, "wrong header Content-Length value");
    return MATCH;
}

int proc_encoding_type_f(char buffer[BUFFER_SIZE], struct header_d *data, int l_s, int l_e) {
    char *pref1 = "Transfer-Encoding:";
    int pref1_len = strlen(pref1);
    char *pref2 = "chunked";
    int pref2_len = strlen(pref2);
    if (strncasecmp(buffer + l_s, pref1, pref1_len)) return NO_MATCH;

    int last_numeric;
    for (int i = l_s + pref1_len; i < l_e; i++) {
        if (strchr(", \t", buffer[i - 1]) && !strchr(", \t", buffer[i]))
            last_numeric = i;
    }
    int ret = strncasecmp(buffer + last_numeric, pref2, pref2_len);
    if (!ret) {
        if (data->chunk_transfer_found) RET_ERR(SYNTAX_ERR, "multiple Transfer-Encoding header fields");
        data->chunk_transfer_found = true;
        data->chunk_transfer = true;
        return MATCH;
    }
    data->chunk_transfer = false;
    return NO_MATCH;
}

int proc_setcookie_f(char buffer[BUFFER_SIZE], struct header_d *data, int l_s, int l_e) {
    char *pref = "Set-Cookie:";
    int pref_len = strlen(pref);
    if (strncasecmp(buffer + l_s, pref, pref_len)) return NO_MATCH;
    int i = pref_len + l_s;
    if (skip_chars(buffer, OWS_CHARSET, &i, l_e)) RET_ERR(SYNTAX_ERR, "invalid Set-Cookie header field syntax");
    int cookie_s = i;
    char* semi = strchr(buffer + cookie_s, ';');
    if (semi == NULL) RET_ERR(SYNTAX_ERR, "invalid Set-Cookie header field syntax");
    int cookie_len = semi - (buffer + cookie_s);
    if (add_cookie(data, buffer, cookie_s, cookie_len)) RET_ERR(SYSTEM_ERR, "memory allocation failed");
    return 0;
}

int proc_next_line(char buffer[BUFFER_SIZE], struct header_d *data, int *line_start, int last_read) {
    char tmp = buffer[last_read + 1];
    buffer[last_read + 1] = 0;
    char* nextCRLF = strstr(buffer + *line_start, CRLF);
    if (nextCRLF == NULL) {
        buffer[last_read + 1] = tmp;
        return NOT_READ_ENOUGHT;
    }
    if (buffer + *line_start == nextCRLF) {
        buffer[last_read + 1] = tmp;
        *line_start += strlen(CRLF);
        return END_OF_HEADER;
    }
    int l_start = *line_start, ret;
    int l_len = nextCRLF - (buffer + *line_start);
    proc_header_f func[LINE_PROC_FUN] = {proc_content_length_f, proc_encoding_type_f, proc_setcookie_f};
    
    ret = NO_MATCH;
    for (int k = 0; k < LINE_PROC_FUN; k++) {
        ret = func[k](buffer, data, l_start, l_start + l_len);
        if (ret) break;
    }
    buffer[last_read + 1] = tmp;
    *line_start = nextCRLF - buffer + 2;
    return ret;
}

void write_to_buff(char buffer[BUFFER_SIZE], int *off, int vars, ...) {
    bool set_off = (off != NULL);
    if (!set_off) {
        int i = 0;
        off = &i;
    }
    va_list valist;
    va_start(valist, vars);
    for (int i = 0; i < vars; i++) {
        char *var = va_arg(valist, char*);
        int vlen = strlen(var);
        assert(*off + vlen < BUFFER_SIZE);
        memcpy(buffer + *off, var, vlen);
        *off += vlen;
    }
    va_end(valist);
}

int lastIndexOf(char *str, char c) {
    int i = 0, f = -1;
    while (str[i] != 0) {
        if (str[i] == c) f = i;
        i++;
    }
    return f;
}

int read_write_cookiesf(char buffer[BUFFER_SIZE], int *offset, char *filename) {
    int set_offset = (offset != NULL);
    char *start = "COOKIE: ";
    if (!set_offset) {
        int i = 0;
        offset = &i;
    }
    FILE *fp = fopen(filename, "r");
    char *line = NULL;
    size_t _l;
    if(fp == NULL) return -1;
    if (ftell(fp) == 0) return 0;

    ssize_t read = 0;

    memcpy(buffer + *offset, start, strlen(start));
    *offset += strlen(start);
    while ((read = getline(&line, &_l, fp)) > 0) {
        int len = strlen(line);
        line[len-1] = ';';
        assert(*offset + len + 1 < BUFFER_SIZE);
        memcpy(buffer + *offset, line, len);
        *offset += strlen(line) + 1;
        buffer[*offset - 1] = SP;
    }
    buffer[*offset-1] = NL;

    free(line);
    fclose(fp);
    return *offset;
}

int send_to_sock(int sock, char buff[BUFFER_SIZE], int bytes) {
    int r, send_bytes = 0;
    do {
        r = write(sock, buff, bytes);
        if (r < 0) RET_ERR(-1, "write fail");
        send_bytes += r;
    } while (send_bytes < bytes);
    return 0;
}

int build_request(char buffer[BUFFER_SIZE], char *cookiefn, char *testAddr) {
    int off = 0, r;
    write_to_buff(buffer, &off, 3, "GET ", testAddr, " HTTP/1.1\n");

    char *ss = strstr(testAddr, "//");
    if (ss == NULL) RET_ERR(-1, "invalid testAddr\n");
    char *netloc_end = strchr(ss + 2, '/');
    if (netloc_end == NULL) RET_ERR(-1, "invalid testAddr\n")
    char tmp = *netloc_end;
    *netloc_end = 0;

    write_to_buff(buffer, &off, 3, "HOST: ", ss + 2, "\n");
    *netloc_end = tmp;
    write_to_buff(buffer, &off, 1, "CONNECTION: CLOSE\n\n");
    r = read_write_cookiesf(buffer, &off, cookiefn);
    if (r < 0) return r;
    return off;
}

int process_request_line(char buffer[BUFFER_SIZE], int sockfd, int *l_line, int *l_read) {
    int r;
    bool end = false;
    char *nextCRLF, tmp;

    while (!end) {
        r = read(sockfd, buffer + *l_read, BUFFER_SIZE - *l_read);
        if (r < 0) RET_ERR(SYSTEM_ERR, "read fail req line");
        if (r == 0) end = true;
        *l_read += r;
        tmp = buffer[*l_read + 1];
        buffer[*l_read + 1] = 0;

        nextCRLF = strstr(buffer + *l_line, CRLF);
        buffer[*l_read + 1] = tmp;
        if (nextCRLF != NULL) end = true;
    }
    buffer[*l_read + 1] = tmp;
    *l_line = nextCRLF - buffer + 2;

    char *p1 = "HTTP/";
    int p1_l = strlen(p1), code;
    if (strncasecmp(buffer, p1, p1_l)) RET_ERR(SYSTEM_ERR, "invalid status line syntax");
    if (buffer[p1_l] != '1') RET_ERR(SYSTEM_ERR, "wrong http version response");
    if (buffer[p1_l + 1] != '.') RET_ERR(SYSTEM_ERR, "invalid status line syntax");
    if (buffer[p1_l + 2] != '1') RET_ERR(SYSTEM_ERR, "invalid status line syntax");
    if (buffer[p1_l + 3] != SP) RET_ERR(SYSTEM_ERR, "invalid status line syntax");
    errno = 0;
    code = strtol(buffer + p1_l + 4, NULL, 10);
    if (errno) RET_ERR(SYSTEM_ERR, "invalid status line syntax");
    if (buffer[p1_l + 7] != SP) RET_ERR(SYSTEM_ERR, "invalid status line syntax");
    return code;
}

void swap_buffer(char buffer[BUFFER_SIZE], int* l_line, int* l_read) {
    int not_read = *l_read - *l_line;
    memmove(buffer, buffer + *l_line, not_read);
    *l_line = 0;
    *l_read = not_read;
}

int read_header_data(char buffer[BUFFER_SIZE], int sock, struct header_d *data, int *l_line, int *l_read) {
    assert(buffer[*l_line] != NL);
    int r;
    bool end = false;

    do {
        if (*l_read > MUL_AND_DIV(BUFFER_SIZE, 3, 4))
            swap_buffer(buffer, l_line, l_read);

        r = read(sock, buffer + *l_read, BUFFER_SIZE - *l_read);
        if (r == -1) RET_ERR(-1, "read fail");
        if (r == 0) end = true;
        *l_read += r;

        if (*l_read > MUL_AND_DIV(BUFFER_SIZE, 3, 4))
            swap_buffer(buffer, l_line, l_read);

        do {
            r = proc_next_line(buffer, data, l_line, *l_read);
            if (r < SYNTAX_ERR) return r;
        } while (r != END_OF_HEADER && r != NOT_READ_ENOUGHT);

        if (r == END_OF_HEADER)
            end = true;

    } while (!end);
    return 0;
}

int64_t read_body_whole(char buffer[BUFFER_SIZE], int sockfd) {
    int r;
    uint64_t read_b = 0;

    while (true) {
        r = read(sockfd, buffer, BUFFER_SIZE);
        if (r == -1) RET_ERR(-1, "read error");
        if (r == 0) break;
        read_b += r;
    }
    return read_b;
}

int read_until_CRLF(char buffer[BUFFER_SIZE], int sockfd, int *l_start, int *l_read) {
    char *crlf;
    int r, total = 0;
    while ((crlf = strstr(buffer + *l_start, CRLF)) == NULL) {
        r = read(sockfd, buffer + *l_read, BUFFER_SIZE - *l_read);
        if (r < 0) RET_ERR(-1, "socket read fail");
        if (r == 0) RET_ERR(-1, "no next CRLF");
        *l_read += r;
        total += r;

        if (*l_read > MUL_AND_DIV(BUFFER_SIZE, 3, 4))
            swap_buffer(buffer, l_start, l_read);
    }
    return total;
}

int push_past_next_CRLF(char buffer[BUFFER_SIZE], int *l_start, int *l_read) {
    char tmp = buffer[*l_read + 1];
    buffer[*l_read + 1] = 0;
    int push_val;
    char *crlf = strstr(buffer + *l_start, CRLF);
    buffer[*l_read + 1] = tmp;
    if (crlf == NULL) {
        *l_start = *l_read;
        return -1;
    }
    push_val = crlf - (buffer + *l_start);
    push_val += strlen(CRLF);
    *l_start += push_val;
    return push_val;
}

/* places *l_start on the n-th byte */
int read_n_bytes(char buffer[BUFFER_SIZE], int sockfd, int nbytes, int *l_start, int *l_read) {
    int r, b_read = 0;
    while (nbytes > b_read) {
        r = read(sockfd, buffer, MIN(nbytes - b_read, BUFFER_SIZE));
        if (r < 0) RET_ERR(-1, "socket read fail");
        if (r == 0) RET_ERR(-1, "coulnd't read whole n_bytes");
        b_read += r;
    }
    memset(buffer, 0, BUFFER_SIZE);
    *l_read = 0;
    *l_start = 0;
    return 0;
}

int read_body_chunked(char buffer[BUFFER_SIZE], int sockfd, int *l_start, int *l_read) {
    int64_t chunk_s = 1, total_size = 0;
    int push;

    while (chunk_s > 0) {
        if (read_until_CRLF(buffer, sockfd, l_start, l_read) < 0) RET_ERR(-1, "cant read next line");

        if (*l_read > MUL_AND_DIV(BUFFER_SIZE, 3, 4))
            swap_buffer(buffer, l_start, l_read);

        errno = 0;
        printf("id = 1, l = %d, r = %d\n", *l_start, *l_read);
        fwrite(buffer + *l_start, 1, *l_read - *l_start, stdout); //DEBUG
        printf("\n");
        chunk_s = strtoll(buffer + *l_start, NULL, 16);
        if (errno) RET_ERR(-1, "chunk size invalid");

        if (chunk_s == 0) break;

        push = push_past_next_CRLF(buffer, l_start, l_read);
        if (push < 0) RET_ERR(-1, "wrong chunk size line")

        while (*l_read - *l_start > chunk_s && chunk_s > 0) {
            total_size += chunk_s;
            *l_start += chunk_s;

            push = push_past_next_CRLF(buffer, l_start, l_read);
            if (push < 0) RET_ERR(-1, "cant push past CRLF\n")
            printf("id = 2, before l = %d, r = %d\n", *l_start, *l_read); //DEBUG
            push = read_until_CRLF(buffer, sockfd, l_start, l_read);
            printf("after l = %d, r = %d\n", *l_start, *l_read); //DEBUG
            if (push < 0) RET_ERR(-1, "cant read next CRLF")

            if (*l_read > MUL_AND_DIV(BUFFER_SIZE, 3, 4))
                swap_buffer(buffer, l_start, l_read);

            errno = 0;
            chunk_s = strtoll(buffer + *l_start, NULL, 16);
            printf("id = 3, l = %d, r = %d\n", *l_start, *l_read);
            fwrite(buffer + *l_start, 1, *l_read - *l_start, stdout); //DEBUG
            printf("\n");
            if (errno) RET_ERR (-1, "chunk size invalid");

            if (push_past_next_CRLF(buffer, l_start, l_read) < 0) RET_ERR(-1, "no next CRLF");
        }

        if (chunk_s == 0) break;
        if (read_n_bytes(buffer, sockfd, chunk_s - *l_read + *l_start, l_start, l_read)) return -1;
        total_size += chunk_s;

        printf("id = 4, before l = %d, r = %d\n", *l_start, *l_read); //DEBUG
        if (read_until_CRLF(buffer, sockfd, l_start, l_read) < 0) RET_ERR(-1, "no next CRLF")
        printf("after l = %d, r = %d\n", *l_start, *l_read); //DEBUG
        push_past_next_CRLF(buffer, l_start, l_read);
    }

    return total_size;
}

int process_response(char buffer[BUFFER_SIZE], int sockfd, struct raport *raport) {
    int l_line = 0, l_read = 0, code;
    struct header_d data;
    header_d_init(&data);
    code = process_request_line(buffer, sockfd, &l_line, &l_read);
    if (code < 0) return code;
    if (code != 200) {
        buffer[l_line - 2] = 0;
        fprintf(stdout, "%s\n", buffer);
        return 0;
    }
    read_header_data(buffer, sockfd, &data, &l_line, &l_read);
    if (header_d_invalid(&data)) RET_ERR(-1, "invalid header data");

    int64_t content_len, already_read;
    already_read = l_read - l_line;
    if (data.content_length_found) {
        content_len = read_body_whole(buffer, sockfd);
        if (content_len < 0) return content_len;
        content_len += already_read;
    } else {
        content_len = read_body_chunked(buffer, sockfd, &l_line, &l_read);
        if (content_len < 0) return content_len;
    }

    raport->real_content_len = content_len;
    raport->cookies_exposition = data.set_cookie;

    return 0;
}

int set_up_conn(char *addr, char *port) {
    struct addrinfo addr_hints, *addr_result;
    int sock = socket(PF_INET, SOCK_STREAM, 0);

    if (sock < 0) RET_ERR(-1, "socker create error")

    memset(&addr_hints, 0, sizeof(struct addrinfo));
    addr_hints.ai_flags = 0;
    addr_hints.ai_family = AF_INET;
    addr_hints.ai_socktype = SOCK_STREAM;
    addr_hints.ai_protocol = IPPROTO_TCP;
    
    int rc = getaddrinfo(addr, port, &addr_hints, &addr_result);
    if (rc != 0) RET_ERR(-1, "ERROR: getaddrinfo fail");

    if (connect(sock, addr_result->ai_addr, addr_result->ai_addrlen) != 0) RET_ERR(-1, "connect fail")
    freeaddrinfo(addr_result);

    return sock;
}

int main(int argv, char *argc[]) {
    char buffer[BUFFER_SIZE];
    char *connAddr, *port;
    int rc;

    assert(argv == ARGS);
    int total = build_request(buffer, argc[2], argc[3]);
    if (total < 0) {
        print_err();
        return 1;
    }

    int semi_index = lastIndexOf(argc[1], ':');
    if (semi_index == -1) {
        fprintf(stderr, "ERROR: no port semicolon given\n");
        return 1;
    }
    if (strlen(argc[1]) == semi_index + 1) {
        fprintf(stderr, "ERROR: no port given\n");
        return 1;
    }
    argc[1][semi_index] = 0;
    connAddr = argc[1];
    port = argc[1] + semi_index + 1;

    int sock = set_up_conn(connAddr, port);
    if (sock < 0) {
        print_err();
        return 1;
    }


    if (send_to_sock(sock, buffer, total) < 0) {
        print_err();
        return 1;
    }

    struct raport raport;
    rc = process_response(buffer, sock, &raport);

    close(sock);

    if (rc) {
        print_err();
        return 1;
    }

    raport_print(raport);
    raport_free(raport);

    return 0;
}