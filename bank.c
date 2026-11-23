#include "bank.h"
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <sched.h>
#include <stdatomic.h>

Account accounts[MAX_ACCOUNTS];

static atomic_int num_accounts;                 /* how many accounts are in use */
static pthread_mutex_t add_lock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_lock  = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t save_lock = PTHREAD_MUTEX_INITIALIZER;

static const char  *default_names[DEMO_ACCOUNTS] = {"Rahul", "Priya", "Amit", "Neha", "Karan"};
static const double default_bal[DEMO_ACCOUNTS]   = {10000, 20000, 30000, 15000, 5000};

static void lock_acc(int i, int safe)   { if (safe) pthread_mutex_lock(&accounts[i].lock); }
static void unlock_acc(int i, int safe) { if (safe) pthread_mutex_unlock(&accounts[i].lock); }

static int valid_idx(int i)      { return i >= 0 && i < atomic_load(&num_accounts); }
static int valid_amt(double amt) { return amt > 0 && amt <= 1e9; }   /* also rejects NaN */

int bank_count(void) { return atomic_load(&num_accounts); }

void bank_init(void) {
    for (int i = 0; i < MAX_ACCOUNTS; i++) {
        accounts[i].id = i + 1;
        accounts[i].owner[0] = '\0';
        accounts[i].balance = 0;
        pthread_mutex_init(&accounts[i].lock, NULL);    /* every slot gets its lock up front */
    }
    for (int i = 0; i < DEMO_ACCOUNTS; i++) {
        snprintf(accounts[i].owner, sizeof accounts[i].owner, "%s", default_names[i]);
        accounts[i].balance = default_bal[i];
    }
    int count = DEMO_ACCOUNTS;

    FILE *f = fopen(DATA_FILE, "r");           /* load saved accounts if the file exists */
    if (f) {
        int id; char name[32]; double bal;
        while (fscanf(f, "%d %31s %lf", &id, name, &bal) == 3) {
            if (id < 1 || id > MAX_ACCOUNTS) continue;
            snprintf(accounts[id - 1].owner, sizeof accounts[id - 1].owner, "%s", name);
            accounts[id - 1].balance = bal;
            if (id > count) count = id;
        }
        fclose(f);
    }
    atomic_store(&num_accounts, count);
}

/* Create a new account. Returns its ID (1-based) or 0 when the bank is full. */
int bank_add_account(const char *owner, double opening) {
    pthread_mutex_lock(&add_lock);               /* only one account is created at a time */
    int n = atomic_load(&num_accounts);
    if (n >= MAX_ACCOUNTS) { pthread_mutex_unlock(&add_lock); return 0; }
    pthread_mutex_lock(&accounts[n].lock);
    snprintf(accounts[n].owner, sizeof accounts[n].owner, "%s", owner);
    accounts[n].balance = opening;
    pthread_mutex_unlock(&accounts[n].lock);
    atomic_store(&num_accounts, n + 1);          /* publish AFTER the slot is fully filled in */
    pthread_mutex_unlock(&add_lock);
    return n + 1;
}

void bank_reset(void) {
    for (int i = 0; i < DEMO_ACCOUNTS; i++) {
        pthread_mutex_lock(&accounts[i].lock);
        accounts[i].balance = default_bal[i];
        pthread_mutex_unlock(&accounts[i].lock);
    }
}

/* Lock ALL accounts in ID order, copy balances, unlock -> a consistent picture */
int bank_snapshot(double bal[MAX_ACCOUNTS]) {
    int n = atomic_load(&num_accounts);
    for (int i = 0; i < n; i++) pthread_mutex_lock(&accounts[i].lock);
    for (int i = 0; i < n; i++) bal[i] = accounts[i].balance;
    for (int i = n - 1; i >= 0; i--) pthread_mutex_unlock(&accounts[i].lock);
    return n;
}

void bank_save(void) {
    double bal[MAX_ACCOUNTS];
    int n = bank_snapshot(bal);
    pthread_mutex_lock(&save_lock);
    FILE *f = fopen(DATA_FILE ".tmp", "w");
    if (f) {
        for (int i = 0; i < n; i++)
            fprintf(f, "%d %s %.2f\n", accounts[i].id, accounts[i].owner, bal[i]);
        fclose(f);
        rename(DATA_FILE ".tmp", DATA_FILE);    /* atomic replace: file is never half-written */
    }
    pthread_mutex_unlock(&save_lock);
}

int deposit(int idx, double amt, int safe) {
    if (!valid_idx(idx) || !valid_amt(amt)) return -1;
    lock_acc(idx, safe);
    double b = accounts[idx].balance;           /* 1. read   */
    if (!safe) sched_yield();                   /* (unsafe mode only: widen the race window) */
    accounts[idx].balance = b + amt;            /* 2. write  */
    unlock_acc(idx, safe);
    return 0;
}

int withdraw(int idx, double amt, int safe) {
    if (!valid_idx(idx) || !valid_amt(amt)) return -1;
    int rc = 0;
    lock_acc(idx, safe);
    if (accounts[idx].balance >= amt) {         /* check */
        double b = accounts[idx].balance;
        if (!safe) sched_yield();
        accounts[idx].balance = b - amt;        /* act   */
    } else rc = -2;
    unlock_acc(idx, safe);
    return rc;
}

int transfer(int from, int to, double amt, int safe) {
    if (!valid_idx(from) || !valid_idx(to) || from == to || !valid_amt(amt)) return -1;
    int first  = from < to ? from : to;         /* lock ordering: lower ID first */
    int second = from < to ? to : from;
    int rc = 0;
    lock_acc(first, safe);
    lock_acc(second, safe);
    if (accounts[from].balance >= amt) {
        double fb = accounts[from].balance, tb = accounts[to].balance;
        if (!safe) sched_yield();
        accounts[from].balance = fb - amt;
        accounts[to].balance   = tb + amt;
    } else rc = -2;
    unlock_acc(second, safe);
    unlock_acc(first, safe);
    return rc;
}

void log_event(const char *fmt, ...) {
    char ts[32];
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", &tmv);

    pthread_mutex_lock(&log_lock);              /* one writer at a time -> lines never mix */
    FILE *f = fopen(LOG_FILE, "a");
    if (f) {
        fprintf(f, "%s ", ts);
        va_list ap; va_start(ap, fmt);
        vfprintf(f, fmt, ap);
        va_end(ap);
        fputc('\n', f);
        fclose(f);
    }
    pthread_mutex_unlock(&log_lock);
}

void read_log_tail(char *out, size_t size) {
    out[0] = '\0';
    pthread_mutex_lock(&log_lock);
    FILE *f = fopen(LOG_FILE, "r");
    if (f) {
        fseek(f, 0, SEEK_END);
        long len = ftell(f);
        long start = len > (long)(size - 1) ? len - (long)(size - 1) : 0;
        fseek(f, start, SEEK_SET);
        size_t n = fread(out, 1, size - 1, f);
        out[n] = '\0';
        fclose(f);
        if (start > 0) {                        /* drop the first partial line */
            char *nl = strchr(out, '\n');
            if (nl) memmove(out, nl + 1, strlen(nl));
        }
    }
    pthread_mutex_unlock(&log_lock);
}
