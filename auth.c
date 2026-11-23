#include "auth.h"
#include "bank.h"
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <pthread.h>

#define MAX_USERS        64
#define MAX_SESSIONS     64
#define SESSION_SECONDS  3600

typedef struct { char username[32]; char password[32]; int is_admin; int account_id; } User;
typedef struct { char sid[33]; int user; time_t created; int used; } Session;

static User users[MAX_USERS];
static int  n_users = 0;
static Session sessions[MAX_SESSIONS];

/* users[] now grows when someone registers, so BOTH tables share one mutex */
static pthread_mutex_t auth_lock = PTHREAD_MUTEX_INITIALIZER;

static void load_users(void) {
    n_users = 0;
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) return;
    User u;
    char role[16];
    while (n_users < MAX_USERS &&
           fscanf(f, "%31s %31s %15s %d", u.username, u.password, role, &u.account_id) == 4) {
        u.is_admin = strcmp(role, "admin") == 0;
        if (!u.is_admin && (u.account_id < 1 || u.account_id > MAX_ACCOUNTS)) continue;  /* bad line */
        users[n_users++] = u;
    }
    fclose(f);
}

void auth_init(void) {
    FILE *f = fopen(USERS_FILE, "r");
    if (!f) {                                    /* first run: create demo users */
        f = fopen(USERS_FILE, "w");
        if (f) {
            fputs("rahul 1234 customer 1\n"
                  "priya 5678 customer 2\n"
                  "amit 1111 customer 3\n"
                  "neha 2222 customer 4\n"
                  "karan 3333 customer 5\n"
                  "admin admin123 admin 0\n", f);
            fclose(f);
        }
    } else fclose(f);
    load_users();
}

/* 16 random bytes from the operating system -> 32 hex characters */
static int make_sid(char sid[33]) {
    unsigned char raw[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return 0;
    size_t n = fread(raw, 1, sizeof raw, f);
    fclose(f);
    if (n != sizeof raw) return 0;
    for (int i = 0; i < 16; i++) snprintf(sid + i * 2, 3, "%02x", raw[i]);
    return 1;
}

int auth_login(const char *user, const char *pass, char sid[33]) {
    char fresh[33];
    if (!make_sid(fresh)) return 0;

    time_t now = time(NULL);
    pthread_mutex_lock(&auth_lock);
    int u = -1;
    for (int i = 0; i < n_users; i++)
        if (strcmp(users[i].username, user) == 0 && strcmp(users[i].password, pass) == 0) { u = i; break; }
    if (u < 0) { pthread_mutex_unlock(&auth_lock); return 0; }

    int slot = -1, oldest = 0;
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (!sessions[i].used || now - sessions[i].created > SESSION_SECONDS) { slot = i; break; }
        if (sessions[i].created < sessions[oldest].created) oldest = i;
    }
    if (slot < 0) slot = oldest;                 /* table full: replace the oldest session */
    sessions[slot].used = 1;
    sessions[slot].user = u;
    sessions[slot].created = now;
    strcpy(sessions[slot].sid, fresh);
    strcpy(sid, fresh);
    pthread_mutex_unlock(&auth_lock);
    return 1;
}

int auth_check(const char *sid, UserInfo *out) {
    if (!sid || strlen(sid) != 32) return 0;
    int ok = 0;
    time_t now = time(NULL);
    pthread_mutex_lock(&auth_lock);
    for (int i = 0; i < MAX_SESSIONS; i++) {
        if (sessions[i].used && strcmp(sessions[i].sid, sid) == 0) {
            if (now - sessions[i].created > SESSION_SECONDS) { sessions[i].used = 0; break; }
            User *u = &users[sessions[i].user];
            strcpy(out->username, u->username);
            out->is_admin = u->is_admin;
            out->account_id = u->account_id;
            ok = 1;
            break;
        }
    }
    pthread_mutex_unlock(&auth_lock);
    return ok;
}

void auth_logout(const char *sid) {
    pthread_mutex_lock(&auth_lock);
    for (int i = 0; i < MAX_SESSIONS; i++)
        if (sessions[i].used && strcmp(sessions[i].sid, sid) == 0) sessions[i].used = 0;
    pthread_mutex_unlock(&auth_lock);
}

int auth_user_exists(const char *user) {
    int found = 0;
    pthread_mutex_lock(&auth_lock);
    for (int i = 0; i < n_users; i++)
        if (strcasecmp(users[i].username, user) == 0) { found = 1; break; }
    pthread_mutex_unlock(&auth_lock);
    return found;
}

/* add a new customer to memory AND to data/users.txt */
int auth_add_user(const char *user, const char *pass, int account_id) {
    int rc = -1;
    pthread_mutex_lock(&auth_lock);
    if (n_users < MAX_USERS) {
        FILE *f = fopen(USERS_FILE, "a");
        if (f) {
            fprintf(f, "%s %s customer %d\n", user, pass, account_id);
            fclose(f);
            User *u = &users[n_users++];
            snprintf(u->username, sizeof u->username, "%s", user);
            snprintf(u->password, sizeof u->password, "%s", pass);
            u->is_admin = 0;
            u->account_id = account_id;
            rc = 0;
        }
    }
    pthread_mutex_unlock(&auth_lock);
    return rc;
}
