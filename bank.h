#ifndef BANK_H
#define BANK_H

#include <pthread.h>

#define MAX_ACCOUNTS  30      /* the bank can hold up to 30 accounts */
#define DEMO_ACCOUNTS 5       /* accounts 1-5 are the demo accounts used by Simulation and Reset */
#define DATA_FILE "data/accounts.txt"
#define LOG_FILE  "data/transactions.log"

typedef struct {
    int id;
    char owner[32];
    double balance;
    pthread_mutex_t lock;      /* one lock per account */
} Account;

extern Account accounts[MAX_ACCOUNTS];

void bank_init(void);
void bank_reset(void);                              /* resets the 5 demo accounts */
void bank_save(void);
int  bank_count(void);                              /* how many accounts exist right now */
int  bank_add_account(const char *owner, double opening);   /* returns new account id, 0 if bank is full */
int  bank_snapshot(double bal[MAX_ACCOUNTS]);       /* consistent copy of all balances, returns count */

/* safe = 1 -> use mutexes, safe = 0 -> NO locks (to demonstrate race conditions)
   return: 0 ok, -1 invalid input, -2 insufficient balance */
int deposit (int idx, double amt, int safe);
int withdraw(int idx, double amt, int safe);
int transfer(int from, int to, double amt, int safe);

void log_event(const char *fmt, ...);
void read_log_tail(char *out, size_t size);

#endif
