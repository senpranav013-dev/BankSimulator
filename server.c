#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <math.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "bank.h"
#include "auth.h"

#define PORT        8080
#define WORKERS     8
#define QUEUE_SIZE  64
#define PAGE_SIZE   32768
#define REQ_SIZE    4096

/* ===================== 1. Job queue (thread pool) ===================== */
static int queue[QUEUE_SIZE];
static int q_head = 0, q_tail = 0, q_count = 0;
static pthread_mutex_t q_lock      = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  q_not_empty = PTHREAD_COND_INITIALIZER;
static pthread_cond_t  q_not_full  = PTHREAD_COND_INITIALIZER;

static void enqueue(int fd) {
    pthread_mutex_lock(&q_lock);
    while (q_count == QUEUE_SIZE) pthread_cond_wait(&q_not_full, &q_lock);
    queue[q_tail] = fd;
    q_tail = (q_tail + 1) % QUEUE_SIZE;
    q_count++;
    pthread_cond_signal(&q_not_empty);
    pthread_mutex_unlock(&q_lock);
}

static int dequeue(void) {
    pthread_mutex_lock(&q_lock);
    while (q_count == 0) pthread_cond_wait(&q_not_empty, &q_lock);
    int fd = queue[q_head];
    q_head = (q_head + 1) % QUEUE_SIZE;
    q_count--;
    pthread_cond_signal(&q_not_full);
    pthread_mutex_unlock(&q_lock);
    return fd;
}

/* ===================== 2. Small helpers ===================== */
typedef struct { char data[PAGE_SIZE]; int len; } Page;

static void add(Page *p, const char *fmt, ...) {
    int room = PAGE_SIZE - p->len;
    if (room <= 1) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(p->data + p->len, room, fmt, ap);
    va_end(ap);
    if (n > 0) p->len += (n < room) ? n : room - 1;
}

static void add_escaped(Page *p, const char *s) {       /* stops HTML injection */
    for (; *s; s++) {
        if      (*s == '<')  add(p, "&lt;");
        else if (*s == '>')  add(p, "&gt;");
        else if (*s == '&')  add(p, "&amp;");
        else if (*s == '\'') add(p, "&#39;");
        else if (*s == '"')  add(p, "&quot;");
        else                 add(p, "%c", *s);
    }
}

/* prints a number the Indian way: 1234567.5 -> 12,34,567.50 */
static void add_money(Page *p, double v) {
    char num[40], res[64];
    int r = 0;
    snprintf(num, sizeof num, "%.2f", v < 0 ? -v : v);
    char *dot = strchr(num, '.');
    int ilen = dot ? (int)(dot - num) : (int)strlen(num);
    if (v < 0) res[r++] = '-';
    for (int i = 0; i < ilen && r < 50; i++) {
        res[r++] = num[i];
        int rem = ilen - i - 1;
        if (rem == 3 || (rem > 3 && (rem - 3) % 2 == 0)) res[r++] = ',';
    }
    res[r] = '\0';
    add(p, "%s%s", res, dot ? dot : "");
}

static void url_decode(char *dst, const char *src, size_t size) {
    size_t n = 0;
    while (*src && n + 1 < size) {
        if (*src == '+') { dst[n++] = ' '; src++; }
        else if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            char hex[3] = {src[1], src[2], 0};
            dst[n++] = (char)strtol(hex, NULL, 16);
            src += 3;
        } else dst[n++] = *src++;
    }
    dst[n] = '\0';
}

static void url_encode(char *dst, const char *src, size_t size) {
    size_t n = 0;
    for (; *src && n + 4 < size; src++) {
        if (isalnum((unsigned char)*src)) dst[n++] = *src;
        else if (*src == ' ') dst[n++] = '+';
        else n += snprintf(dst + n, size - n, "%%%02X", (unsigned char)*src);
    }
    dst[n] = '\0';
}

/* find key=value inside "a=1&b=2" (works for form bodies and query strings) */
static int get_param(const char *data, const char *key, char *out, size_t size) {
    size_t klen = strlen(key);
    const char *p = data;
    while (p && *p) {
        if (strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *v = p + klen + 1;
            size_t n = strcspn(v, "& \r\n");
            char raw[256];
            if (n >= sizeof raw) n = sizeof raw - 1;
            memcpy(raw, v, n); raw[n] = '\0';
            url_decode(out, raw, size);
            return 1;
        }
        const char *amp = strchr(p, '&');
        p = amp ? amp + 1 : NULL;
    }
    out[0] = '\0';
    return 0;
}

/* find one cookie value (e.g. sid) inside the "Cookie:" header line */
static int get_cookie(const char *req, size_t hdr_len, const char *name, char *out, size_t size) {
    const char *end = req + hdr_len;
    const char *line = req;
    size_t nlen = strlen(name);
    while (line < end) {
        if (strncasecmp(line, "Cookie:", 7) == 0) {
            const char *p = line + 7;
            while (p < end && *p != '\r' && *p != '\n') {
                while (*p == ' ' || *p == ';') p++;
                if (strncmp(p, name, nlen) == 0 && p[nlen] == '=') {
                    p += nlen + 1;
                    size_t n = strcspn(p, "; \r\n");
                    if (n >= size) n = size - 1;
                    memcpy(out, p, n); out[n] = '\0';
                    return 1;
                }
                while (p < end && *p != ';' && *p != '\r' && *p != '\n') p++;
            }
        }
        const char *nl = memchr(line, '\n', (size_t)(end - line));
        if (!nl) break;
        line = nl + 1;
    }
    out[0] = '\0';
    return 0;
}

/* keep only letters, digits and _ so user-typed text can never forge a log line */
static void clean_name(char *dst, const char *src, size_t size) {
    size_t n = 0;
    for (; *src && n + 1 < size; src++)
        dst[n++] = (isalnum((unsigned char)*src) || *src == '_') ? *src : '?';
    dst[n] = '\0';
}

/* sign-up rules: the users file is split on spaces, so spaces are not allowed */
static int valid_username(const char *s) {
    size_t n = strlen(s);
    if (n < 3 || n > 20) return 0;
    for (; *s; s++) if (!isalnum((unsigned char)*s) && *s != '_') return 0;
    return 1;
}

static int valid_password(const char *s) {
    size_t n = strlen(s);
    if (n < 4 || n > 30) return 0;
    for (; *s; s++) if ((unsigned char)*s < 33 || (unsigned char)*s > 126) return 0;
    return 1;
}

static void send_all(int fd, const char *buf, size_t len) {
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n <= 0) return;
        buf += n; len -= (size_t)n;
    }
}

static void send_response(int fd, const char *status, const char *ctype, const char *body, int len) {
    char hdr[256];
    int h = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 %s\r\nContent-Type: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
        status, ctype, len);
    send_all(fd, hdr, (size_t)h);
    send_all(fd, body, (size_t)len);
}

static void send_page(int fd, Page *p) { send_response(fd, "200 OK", "text/html; charset=utf-8", p->data, p->len); }

/* 303 redirect, optionally with a Set-Cookie header */
static void send_redirect(int fd, const char *location, const char *cookie) {
    char hdr[640];
    int h = snprintf(hdr, sizeof hdr,
        "HTTP/1.1 303 See Other\r\nLocation: %s\r\n%s%sContent-Length: 0\r\nConnection: close\r\n\r\n",
        location, cookie ? cookie : "", cookie ? "\r\n" : "");
    send_all(fd, hdr, (size_t)h);
}

/* redirect to the dashboard with a green (ok=1) or red (ok=0) message */
static void redirect(int fd, int ok, const char *msg) {
    char enc[256], loc[320];
    url_encode(enc, msg, sizeof enc);
    snprintf(loc, sizeof loc, "/?ok=%d&msg=%s", ok, enc);
    send_redirect(fd, loc, NULL);
}

static int content_length(const char *req) {
    const char *p = req;
    while ((p = strchr(p, '\n')) != NULL) {
        p++;
        if (strncasecmp(p, "Content-Length:", 15) == 0) return atoi(p + 15);
    }
    return 0;
}

static int read_request(int fd, char *buf, size_t size) {
    size_t total = 0;
    while (total < size - 1) {
        ssize_t n = read(fd, buf + total, size - 1 - total);
        if (n <= 0) break;
        total += (size_t)n;
        buf[total] = '\0';
        char *end = strstr(buf, "\r\n\r\n");
        if (end) {
            size_t have = total - (size_t)(end + 4 - buf);
            if (have >= (size_t)content_length(buf)) break;
        }
    }
    return (int)total;
}

/* ===================== 3. HTML building blocks ===================== */
static void nav_link(Page *p, const char *title, const char *key, const char *href, const char *label) {
    add(p, "<a href='%s'%s>%s</a>", href, strcmp(title, key) == 0 ? " class='active'" : "", label);
}

/* u == NULL means "not logged in" (login / register pages): no menu bar */
static void page_head(Page *p, const char *title, int refresh, const UserInfo *u) {
    add(p, "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
           "<meta name='viewport' content='width=device-width, initial-scale=1'>");
    if (refresh) add(p, "<meta http-equiv='refresh' content='%d'>", refresh);
    add(p, "<title>%s | Thread-Safe Bank</title><link rel='stylesheet' href='/style.css'></head>"
           "<body class='%s'>", title, u ? "app" : "auth");
    if (u) {
        add(p, "<header><div class='bar'><a class='brand' href='/'><span class='logo'>&#127974;</span>"
               "<span><b>Thread-Safe Bank</b><small>Concurrent transaction simulator</small></span></a><nav>");
        nav_link(p, title, "Dashboard", "/", "Dashboard");
        if (u->is_admin) {
            nav_link(p, title, "Simulation", "/simulate", "Simulation");
            nav_link(p, title, "Live view", "/live", "Live view");
            nav_link(p, title, "Log", "/log", "Log");
        } else {
            nav_link(p, title, "Log", "/log", "My transactions");
        }
        add(p, "<a class='out' href='/logout'>Logout</a>"
               "<span class='who'><span class='avatar'>%c</span><span>", toupper((unsigned char)u->username[0]));
        add_escaped(p, u->username);
        add(p, " <em class='role %s'>%s</em></span></span></nav></div></header><main>",
            u->is_admin ? "admin" : "cust", u->is_admin ? "admin" : "customer");
    } else {
        add(p, "<main class='auth-main'>");
    }
}

static void page_foot(Page *p, const UserInfo *u) {
    add(p, "</main>");
    if (u) add(p, "<footer>Built with C &middot; HTML &middot; CSS &nbsp;|&nbsp; "
                  "Mutex-protected, deadlock-free transactions</footer>");
    add(p, "</body></html>");
}

static void add_stats(Page *p, const double bal[MAX_ACCOUNTS], int n) {
    double total = 0;
    for (int i = 0; i < n; i++) total += bal[i];
    add(p, "<div class='stats'>"
           "<div class='stat s1'><span>Total bank money</span><b>&#8377; ");
    add_money(p, total);
    add(p, "</b></div><div class='stat s2'><span>Open accounts</span><b>%d</b></div>"
           "<div class='stat s3'><span>Mutex locks (one per account)</span><b>%d</b></div></div>", n, n);
}

static void add_table(Page *p, const double bal[MAX_ACCOUNTS], int n) {
    add(p, "<div class='card tablecard'><table><tr><th>ID</th><th>Owner</th>"
           "<th class='num'>Balance (&#8377;)</th></tr>");
    for (int i = 0; i < n; i++) {
        add(p, "<tr><td>#%d</td><td><span class='dot'></span>", accounts[i].id);
        add_escaped(p, accounts[i].owner);
        add(p, "</td><td class='num %s'>", bal[i] < 0 ? "neg" : "");
        add_money(p, bal[i]);
        add(p, "</td></tr>");
    }
    add(p, "</table></div>");
}

/* dropdown of accounts; exclude_id = 0 shows all, otherwise hides that account */
static void add_options(Page *p, const char *name, int exclude_id, int n) {
    add(p, "<select name='%s'>", name);
    for (int i = 0; i < n; i++) {
        if (accounts[i].id == exclude_id) continue;
        add(p, "<option value='%d'>#%d - ", accounts[i].id, accounts[i].id);
        add_escaped(p, accounts[i].owner);
        add(p, "</option>");
    }
    add(p, "</select>");
}

/* ===================== 4. Login + register pages ===================== */
static void add_hero(Page *p) {
    add(p, "<section class='hero'><span class='logo big'>&#127974;</span><h1>Thread-Safe Bank</h1>"
           "<p>A banking simulator that stays correct even when hundreds of transactions happen at once.</p>"
           "<ul><li>One mutex lock per account</li><li>Deadlock-free ordered transfers</li>"
           "<li>Live race-condition demo</li><li>Written in C, HTML and CSS only</li></ul></section>");
}

static void route_login(int fd, const char *query) {
    Page p = { .len = 0 };
    char code[8];
    get_param(query, "m", code, sizeof code);

    page_head(&p, "Login", 0, NULL);
    add(&p, "<div class='auth-wrap'>");
    add_hero(&p);
    add(&p, "<form method='POST' action='/login' class='card auth-card'>"
            "<h2>Welcome back</h2><p class='sub'>Sign in to your account</p>");
    if (code[0] == '1')      add(&p, "<div class='msg err'>Invalid username or password</div>");
    else if (code[0] == '2') add(&p, "<div class='msg err'>Please log in to continue</div>");
    else if (code[0] == '3') add(&p, "<div class='msg ok'>You have been logged out</div>");
    add(&p, "<label>Username</label><input type='text' name='user' required autofocus>"
            "<label>Password</label><input type='password' name='pass' required>"
            "<button class='btn'>Sign in</button>"
            "<p class='switch'>New here? <a href='/register'>Create an account</a></p>"
            "<p class='demo'>Demo: <b>rahul</b> / 1234 &nbsp;&middot;&nbsp; <b>admin</b> / admin123</p>"
            "</form></div>");
    page_foot(&p, NULL);
    send_page(fd, &p);
}

static void route_register(int fd, const char *query) {
    Page p = { .len = 0 };
    char code[8];
    get_param(query, "m", code, sizeof code);

    page_head(&p, "Register", 0, NULL);
    add(&p, "<div class='auth-wrap'>");
    add_hero(&p);
    add(&p, "<form method='POST' action='/register' class='card auth-card'>"
            "<h2>Create your account</h2><p class='sub'>Open a new bank account in seconds</p>");
    switch (code[0]) {
        case '1': add(&p, "<div class='msg err'>Username must be 3-20 letters, digits or underscore</div>"); break;
        case '2': add(&p, "<div class='msg err'>Password must be 4-30 characters with no spaces</div>"); break;
        case '3': add(&p, "<div class='msg err'>The two passwords do not match</div>"); break;
        case '4': add(&p, "<div class='msg err'>That username is already taken</div>"); break;
        case '5': add(&p, "<div class='msg err'>Opening deposit must be between 0 and 100000</div>"); break;
        case '6': add(&p, "<div class='msg err'>Sorry, the bank is full (maximum accounts reached)</div>"); break;
        case '7': add(&p, "<div class='msg err'>Could not create the account, please try again</div>"); break;
        default: break;
    }
    add(&p, "<label>Username</label>"
            "<input type='text' name='user' required autofocus minlength='3' maxlength='20' "
            "pattern='[A-Za-z0-9_]{3,20}' title='3-20 letters, digits or underscore' placeholder='e.g. meera_k'>"
            "<label>Password</label>"
            "<input type='password' name='pass' required minlength='4' maxlength='30' placeholder='At least 4 characters'>"
            "<label>Confirm password</label>"
            "<input type='password' name='pass2' required minlength='4' maxlength='30'>"
            "<label>Opening deposit (&#8377;)</label>"
            "<input type='number' name='deposit' min='0' max='100000' step='0.01' value='1000' required>"
            "<button class='btn'>Create account</button>"
            "<p class='switch'>Already have an account? <a href='/login'>Sign in</a></p>"
            "</form></div>");
    page_foot(&p, NULL);
    send_page(fd, &p);
}

static void route_login_post(int fd, const char *body) {
    char user[64], pass[64], sid[33];
    get_param(body, "user", user, sizeof user);
    get_param(body, "pass", pass, sizeof pass);

    if (auth_login(user, pass, sid)) {
        char cookie[160];
        snprintf(cookie, sizeof cookie, "Set-Cookie: sid=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600", sid);
        log_event("LOGIN OK by=%s", user);
        send_redirect(fd, "/", cookie);
    } else {
        char shown[32];
        clean_name(shown, user, sizeof shown);
        log_event("LOGIN FAILED user=%s", shown);
        usleep(300000);                       /* small delay slows down password guessing */
        send_redirect(fd, "/login?m=1", NULL);
    }
}

/* only one sign-up at a time, so two people can't grab the same username */
static pthread_mutex_t reg_lock = PTHREAD_MUTEX_INITIALIZER;

static void route_register_post(int fd, const char *body) {
    char user[64], pass[64], pass2[64], sdep[32], sid[33];
    get_param(body, "user", user, sizeof user);
    get_param(body, "pass", pass, sizeof pass);
    get_param(body, "pass2", pass2, sizeof pass2);
    get_param(body, "deposit", sdep, sizeof sdep);
    double dep = sdep[0] ? atof(sdep) : 0;

    if (!valid_username(user))        { send_redirect(fd, "/register?m=1", NULL); return; }
    if (!valid_password(pass))        { send_redirect(fd, "/register?m=2", NULL); return; }
    if (strcmp(pass, pass2) != 0)     { send_redirect(fd, "/register?m=3", NULL); return; }
    if (!(dep >= 0 && dep <= 100000)) { send_redirect(fd, "/register?m=5", NULL); return; }

    pthread_mutex_lock(&reg_lock);
    if (auth_user_exists(user)) { pthread_mutex_unlock(&reg_lock); send_redirect(fd, "/register?m=4", NULL); return; }
    int acc = bank_add_account(user, dep);
    if (acc == 0)               { pthread_mutex_unlock(&reg_lock); send_redirect(fd, "/register?m=6", NULL); return; }
    if (auth_add_user(user, pass, acc) != 0) {
        pthread_mutex_unlock(&reg_lock);
        send_redirect(fd, "/register?m=7", NULL);
        return;
    }
    pthread_mutex_unlock(&reg_lock);

    bank_save();
    log_event("OPEN ACCOUNT acc=%d opening=%.2f by=%s", acc, dep, user);

    if (auth_login(user, pass, sid)) {               /* log the new customer in straight away */
        char cookie[160], enc[128], loc[192];
        snprintf(cookie, sizeof cookie, "Set-Cookie: sid=%s; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600", sid);
        url_encode(enc, "Account created. Welcome to the bank!", sizeof enc);
        snprintf(loc, sizeof loc, "/?ok=1&msg=%s", enc);
        send_redirect(fd, loc, cookie);
    } else {
        send_redirect(fd, "/login", NULL);
    }
}

/* ===================== 5. Bank pages ===================== */
static void route_dashboard(int fd, const char *query, int live, const UserInfo *u) {
    Page p = { .len = 0 };
    char msg[128], ok[8];
    int has_msg = get_param(query, "msg", msg, sizeof msg);
    get_param(query, "ok", ok, sizeof ok);

    double bal[MAX_ACCOUNTS];
    int n = bank_snapshot(bal);

    page_head(&p, live ? "Live view" : "Dashboard", live ? 2 : 0, u);
    if (has_msg && !live) {
        add(&p, "<div class='msg %s'>", ok[0] == '1' ? "ok" : "err");
        add_escaped(&p, msg);
        add(&p, "</div>");
    }

    if (u->is_admin) {                                   /* ---- admin: sees everything ---- */
        add(&p, "<h2 class='page-title'>%s</h2>", live ? "Live balances <small>refreshes every 2 seconds</small>" : "All accounts");
        add_stats(&p, bal, n);
        add_table(&p, bal, n);
        if (!live) {
            add(&p, "<div class='grid'>");
            add(&p, "<form method='POST' action='/deposit' class='card tx dep'><h3>&#128181; Deposit</h3>"
                    "<label>Account</label>");
            add_options(&p, "id", 0, n);
            add(&p, "<label>Amount (&#8377;)</label><input type='number' name='amt' min='1' step='0.01' placeholder='0.00' required>"
                    "<button class='btn'>Deposit</button></form>");
            add(&p, "<form method='POST' action='/withdraw' class='card tx wd'><h3>&#128184; Withdraw</h3>"
                    "<label>Account</label>");
            add_options(&p, "id", 0, n);
            add(&p, "<label>Amount (&#8377;)</label><input type='number' name='amt' min='1' step='0.01' placeholder='0.00' required>"
                    "<button class='btn'>Withdraw</button></form>");
            add(&p, "<form method='POST' action='/transfer' class='card tx tr'><h3>&#128260; Transfer</h3>"
                    "<label>From</label>");
            add_options(&p, "from", 0, n);
            add(&p, "<label>To</label>");
            add_options(&p, "to", 0, n);
            add(&p, "<label>Amount (&#8377;)</label><input type='number' name='amt' min='1' step='0.01' placeholder='0.00' required>"
                    "<button class='btn'>Transfer</button></form></div>");
            add(&p, "<form method='POST' action='/reset' class='inline'>"
                    "<button class='btn danger'>Reset demo accounts</button>"
                    "<small>Restores accounts #1-#5 to their starting balances</small></form>");
        }
    } else {                                             /* ---- customer: only own account ---- */
        int me = u->account_id - 1;
        if (me < 0 || me >= n) {
            add(&p, "<div class='msg err'>Your bank account was not found. Please contact the admin.</div>");
        } else {
            add(&p, "<section class='balance-card'><div><span class='label'>Available balance</span>"
                    "<div class='amount %s'>&#8377; ", bal[me] < 0 ? "neg" : "");
            add_money(&p, bal[me]);
            add(&p, "</div><span class='acct-no'>Account #%d &middot; ", accounts[me].id);
            add_escaped(&p, accounts[me].owner);
            add(&p, "</span></div><span class='chip'>&#128274; Protected by a mutex lock</span></section>");

            add(&p, "<div class='grid'>");
            add(&p, "<form method='POST' action='/deposit' class='card tx dep'><h3>&#128181; Deposit</h3>"
                    "<p class='acct'>Add money to your account</p>"
                    "<label>Amount (&#8377;)</label><input type='number' name='amt' min='1' step='0.01' placeholder='0.00' required>"
                    "<button class='btn'>Deposit</button></form>");
            add(&p, "<form method='POST' action='/withdraw' class='card tx wd'><h3>&#128184; Withdraw</h3>"
                    "<p class='acct'>Take money from your account</p>"
                    "<label>Amount (&#8377;)</label><input type='number' name='amt' min='1' step='0.01' placeholder='0.00' required>"
                    "<button class='btn'>Withdraw</button></form>");
            add(&p, "<form method='POST' action='/transfer' class='card tx tr'><h3>&#128260; Transfer</h3>"
                    "<label>To account</label>");
            add_options(&p, "to", accounts[me].id, n);
            add(&p, "<label>Amount (&#8377;)</label><input type='number' name='amt' min='1' step='0.01' placeholder='0.00' required>"
                    "<button class='btn'>Transfer</button></form></div>");
        }
    }
    page_foot(&p, u);
    send_page(fd, &p);
}

static void route_transaction(int fd, const char *path, const char *body, const UserInfo *u) {
    char sid[16], sfrom[16], sto[16], samt[32];
    get_param(body, "id", sid, sizeof sid);
    get_param(body, "from", sfrom, sizeof sfrom);
    get_param(body, "to", sto, sizeof sto);
    get_param(body, "amt", samt, sizeof samt);
    double amt = atof(samt);

    /* SECURITY: a customer can only touch their own account, whatever the form says */
    int acc  = u->is_admin ? atoi(sid)   : u->account_id;
    int from = u->is_admin ? atoi(sfrom) : u->account_id;
    int to   = atoi(sto);

    int rc;
    const char *okmsg;
    if (strcmp(path, "/deposit") == 0) {
        rc = deposit(acc - 1, amt, 1);
        okmsg = "Deposit successful";
        log_event("DEPOSIT acc=%d amt=%.2f %s by=%s", acc, amt, rc == 0 ? "OK" : "FAILED", u->username);
    } else if (strcmp(path, "/withdraw") == 0) {
        rc = withdraw(acc - 1, amt, 1);
        okmsg = "Withdrawal successful";
        log_event("WITHDRAW acc=%d amt=%.2f %s by=%s", acc, amt, rc == 0 ? "OK" : "FAILED", u->username);
    } else {
        rc = transfer(from - 1, to - 1, amt, 1);
        okmsg = "Transfer successful";
        log_event("TRANSFER from=%d to=%d amt=%.2f %s by=%s", from, to, amt, rc == 0 ? "OK" : "FAILED", u->username);
    }
    if (rc == 0) bank_save();
    redirect(fd, rc == 0, rc == 0 ? okmsg : rc == -2 ? "Insufficient balance" : "Invalid input");
}

/* ---------- simulation (admin only, touches only the 5 demo accounts) ---------- */
typedef struct { int ops; int safe; unsigned seed; } SimArg;

typedef struct {
    int safe, threads, ops;
    double before, expected, actual;
    int negatives;
    double ms;
} SimResult;

static pthread_mutex_t sim_lock = PTHREAD_MUTEX_INITIALIZER;

static void *sim_worker(void *arg) {
    SimArg *a = arg;
    for (int i = 0; i < a->ops; i++) {
        deposit(0, 1, a->safe);                              /* every thread adds Rs 1 to account 1 */
        int from = rand_r(&a->seed) % DEMO_ACCOUNTS;
        int to   = rand_r(&a->seed) % DEMO_ACCOUNTS;
        double amt = 1 + rand_r(&a->seed) % 50;
        transfer(from, to, amt, a->safe);                    /* money only moves, never created */
    }
    return NULL;
}

static void run_simulation(int threads, int ops, int safe, SimResult *r) {
    pthread_t tid[100];
    SimArg args[100];
    double bal[MAX_ACCOUNTS];

    pthread_mutex_lock(&sim_lock);                           /* only one simulation at a time */
    bank_snapshot(bal);
    r->before = 0;
    for (int i = 0; i < DEMO_ACCOUNTS; i++) r->before += bal[i];

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    for (int i = 0; i < threads; i++) {
        args[i] = (SimArg){ ops, safe, (unsigned)(i * 7919 + 17) };
        pthread_create(&tid[i], NULL, sim_worker, &args[i]);
    }
    for (int i = 0; i < threads; i++) pthread_join(tid[i], NULL);
    clock_gettime(CLOCK_MONOTONIC, &t1);

    bank_snapshot(bal);
    r->actual = 0; r->negatives = 0;
    for (int i = 0; i < DEMO_ACCOUNTS; i++) { r->actual += bal[i]; if (bal[i] < 0) r->negatives++; }
    r->expected = r->before + (double)threads * ops;
    r->safe = safe; r->threads = threads; r->ops = ops;
    r->ms = (t1.tv_sec - t0.tv_sec) * 1000.0 + (t1.tv_nsec - t0.tv_nsec) / 1e6;
    pthread_mutex_unlock(&sim_lock);
}

static void route_simulate(int fd, const SimResult *r, const UserInfo *u) {
    Page p = { .len = 0 };
    page_head(&p, "Simulation", 0, u);
    add(&p, "<h2 class='page-title'>Concurrency simulation</h2>"
            "<div class='card'><p>Many threads hit the bank at the same time. Each thread repeats: "
            "<b>deposit &#8377;1 to account #1</b> and <b>transfer a random amount between two random demo accounts</b>. "
            "Correct result: total money = start total + (threads &times; operations). "
            "Only the 5 demo accounts are used, so real customer accounts are never touched.</p></div>"
            "<form method='POST' action='/simulate' class='card sim'>"
            "<label>Threads (1-100)</label><input type='number' name='threads' value='50' min='1' max='100'>"
            "<label>Operations per thread (1-2000)</label><input type='number' name='ops' value='1000' min='1' max='2000'>"
            "<label>Mode</label><select name='mode'>"
            "<option value='safe'>Safe (mutexes ON)</option>"
            "<option value='unsafe'>Unsafe (mutexes OFF)</option></select>"
            "<button class='btn'>Run simulation</button></form>");
    if (r) {
        int pass = fabs(r->expected - r->actual) < 0.005 && r->negatives == 0;
        add(&p, "<div class='card result %s'><h3>%s &mdash; %s</h3><table class='kv'>"
                "<tr><td>Mode</td><td>%s</td></tr>"
                "<tr><td>Threads &times; operations</td><td>%d &times; %d</td></tr>"
                "<tr><td>Time taken</td><td>%.1f ms</td></tr>"
                "<tr><td>Total before</td><td>%.2f</td></tr>"
                "<tr><td>Expected total after</td><td>%.2f</td></tr>"
                "<tr><td>Actual total after</td><td>%.2f</td></tr>"
                "<tr><td>Money lost / created</td><td>%.2f</td></tr>"
                "<tr><td>Negative balances</td><td>%d</td></tr></table></div>",
            pass ? "ok" : "err", pass ? "&#10004; PASS" : "&#10008; FAIL",
            pass ? "no data corruption" : "race condition detected",
            r->safe ? "Safe (mutexes ON)" : "Unsafe (mutexes OFF)",
            r->threads, r->ops, r->ms, r->before, r->expected, r->actual,
            r->actual - r->expected, r->negatives);
    }
    add(&p, "<p class='hint'>Tip: click <b>Reset demo accounts</b> on the Dashboard between runs.</p>");
    page_foot(&p, u);
    send_page(fd, &p);
}

static void route_simulate_post(int fd, const char *body, const UserInfo *u) {
    char s_threads[16], s_ops[16], s_mode[16];
    get_param(body, "threads", s_threads, sizeof s_threads);
    get_param(body, "ops", s_ops, sizeof s_ops);
    get_param(body, "mode", s_mode, sizeof s_mode);
    int threads = atoi(s_threads), ops = atoi(s_ops);
    if (threads < 1) threads = 1;
    if (threads > 100) threads = 100;
    if (ops < 1) ops = 1;
    if (ops > 2000) ops = 2000;
    int safe = strcmp(s_mode, "unsafe") != 0;

    SimResult r;
    run_simulation(threads, ops, safe, &r);
    log_event("SIMULATION mode=%s threads=%d ops=%d expected=%.2f actual=%.2f negatives=%d by=%s",
              safe ? "SAFE" : "UNSAFE", threads, ops, r.expected, r.actual, r.negatives, u->username);
    bank_save();
    route_simulate(fd, &r, u);
}

/* colour-coded log line */
static void add_log_line(Page *p, const char *line) {
    const char *cls = "good";
    if (strstr(line, "FAILED")) cls = "bad";
    else if (strstr(line, " LOGIN") || strstr(line, " LOGOUT") || strstr(line, "OPEN ACCOUNT")) cls = "info";
    else if (strstr(line, "SIMULATION") || strstr(line, "RESET")) cls = "sim";
    add(p, "<div class='logline %s'>", cls);
    add_escaped(p, line);
    add(p, "</div>");
}

/* admin sees the whole log, a customer sees only lines ending in "by=<their username>" */
static void route_log(int fd, const UserInfo *u) {
    Page p = { .len = 0 };
    char buf[16384], *lines[300], *save = NULL;
    int n = 0;
    read_log_tail(buf, u->is_admin ? 8192 : sizeof buf);

    char suffix[48];
    snprintf(suffix, sizeof suffix, " by=%s", u->username);
    size_t slen = strlen(suffix);
    for (char *line = strtok_r(buf, "\n", &save); line && n < 300; line = strtok_r(NULL, "\n", &save)) {
        size_t len = strlen(line);
        if (u->is_admin || (len >= slen && strcmp(line + len - slen, suffix) == 0)) lines[n++] = line;
    }

    page_head(&p, "Log", 0, u);
    add(&p, "<h2 class='page-title'>%s <small>newest first</small></h2><div class='card logbox'>",
        u->is_admin ? "Transaction log" : "My transactions");
    if (n == 0) add(&p, "<p class='empty'>No transactions yet.</p>");
    for (int i = n - 1; i >= 0 && p.len < PAGE_SIZE - 800; i--) add_log_line(&p, lines[i]);
    add(&p, "</div>");
    page_foot(&p, u);
    send_page(fd, &p);
}

static void route_css(int fd) {
    static const char *not_found = "Not found";
    char buf[32768];
    FILE *f = fopen("style.css", "r");
    if (!f) { send_response(fd, "404 Not Found", "text/plain", not_found, (int)strlen(not_found)); return; }
    size_t n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    send_response(fd, "200 OK", "text/css", buf, (int)n);
}

/* ===================== 6. Request dispatcher + workers ===================== */
static void handle_client(int fd) {
    char req[REQ_SIZE];
    if (read_request(fd, req, sizeof req) <= 0) return;

    char method[8], path[256];
    if (sscanf(req, "%7s %255s", method, path) != 2) return;
    char *hdr_end = strstr(req, "\r\n\r\n");
    char *body = hdr_end ? hdr_end + 4 : "";
    size_t hdr_len = hdr_end ? (size_t)(hdr_end - req) : strlen(req);
    char *query = strchr(path, '?');
    if (query) *query++ = '\0'; else query = "";

    int is_post = strcmp(method, "POST") == 0;

    /* pages anyone may open */
    if (!is_post && strcmp(path, "/style.css") == 0) { route_css(fd); return; }

    /* who is this? read the session cookie */
    char sid[40];
    get_cookie(req, hdr_len, "sid", sid, sizeof sid);
    UserInfo u;
    int logged = auth_check(sid, &u);

    if (strcmp(path, "/login") == 0) {
        if (is_post)       route_login_post(fd, body);
        else if (logged)   send_redirect(fd, "/", NULL);
        else               route_login(fd, query);
        return;
    }
    if (strcmp(path, "/register") == 0) {
        if (is_post)       route_register_post(fd, body);
        else if (logged)   send_redirect(fd, "/", NULL);
        else               route_register(fd, query);
        return;
    }
    if (strcmp(path, "/logout") == 0) {
        if (logged) log_event("LOGOUT by=%s", u.username);
        auth_logout(sid);
        send_redirect(fd, "/login?m=3", "Set-Cookie: sid=; Path=/; Max-Age=0");
        return;
    }

    /* everything below needs a login */
    if (!logged) { send_redirect(fd, "/login?m=2", NULL); return; }

    /* admin-only pages */
    int admin_only = (!is_post && (strcmp(path, "/simulate") == 0 || strcmp(path, "/live") == 0)) ||
                     ( is_post && (strcmp(path, "/simulate") == 0 || strcmp(path, "/reset") == 0));
    if (admin_only && !u.is_admin) { redirect(fd, 0, "Admin access only"); return; }

    if      (!is_post && strcmp(path, "/") == 0)         route_dashboard(fd, query, 0, &u);
    else if (!is_post && strcmp(path, "/live") == 0)     route_dashboard(fd, query, 1, &u);
    else if (!is_post && strcmp(path, "/simulate") == 0) route_simulate(fd, NULL, &u);
    else if (!is_post && strcmp(path, "/log") == 0)      route_log(fd, &u);
    else if (is_post && strcmp(path, "/simulate") == 0)  route_simulate_post(fd, body, &u);
    else if (is_post && (strcmp(path, "/deposit") == 0 || strcmp(path, "/withdraw") == 0 ||
                         strcmp(path, "/transfer") == 0)) route_transaction(fd, path, body, &u);
    else if (is_post && strcmp(path, "/reset") == 0) {
        bank_reset(); bank_save(); log_event("RESET demo accounts by=%s", u.username);
        redirect(fd, 1, "Demo accounts reset");
    } else {
        const char *m = "404 - Page not found";
        send_response(fd, "404 Not Found", "text/plain", m, (int)strlen(m));
    }
}

static void *worker(void *arg) {
    (void)arg;
    for (;;) {
        int fd = dequeue();
        handle_client(fd);
        close(fd);
    }
    return NULL;
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);              /* don't crash if a browser closes the connection early */
    mkdir("data", 0755);
    bank_init();
    bank_save();
    auth_init();                           /* load users (creates data/users.txt on first run) */

    for (int i = 0; i < WORKERS; i++) {
        pthread_t t;
        pthread_create(&t, NULL, worker, NULL);
        pthread_detach(t);
    }

    int s = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof opt);
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(PORT);
    if (bind(s, (struct sockaddr *)&addr, sizeof addr) < 0) { perror("bind"); return 1; }
    if (listen(s, 64) < 0) { perror("listen"); return 1; }
    printf("Bank simulator running: open http://localhost:%d\n", PORT);

    for (;;) {
        int c = accept(s, NULL, NULL);
        if (c < 0) continue;
        struct timeval tv = {3, 0};        /* browsers open idle connections: don't let them block a worker */
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        enqueue(c);
    }
}
