#ifndef AUTH_H
#define AUTH_H

#define USERS_FILE "data/users.txt"

typedef struct {
    char username[32];
    int  is_admin;      /* 1 = admin, 0 = customer */
    int  account_id;    /* customer's own account (1-based), 0 for admin */
} UserInfo;

void auth_init(void);                                              /* load (or create) users file */
int  auth_login(const char *user, const char *pass, char sid[33]); /* 1 = ok, sid filled in */
int  auth_check(const char *sid, UserInfo *out);                   /* 1 = valid session */
void auth_logout(const char *sid);
int  auth_user_exists(const char *user);                           /* 1 = taken (ignores upper/lower case) */
int  auth_add_user(const char *user, const char *pass, int account_id);  /* 0 = ok, -1 = failed */

#endif
