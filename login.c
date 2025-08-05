#include<stdio.h>
#include<errno.h>
#include<stdatomic.h>
#include<time.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<pthread.h>
#include<stdint.h>
#include<fcntl.h>
#include<argon2.h>
#include<sys/mman.h>

#include<sys/epoll.h>
#include<sys/socket.h>
#include<arpa/inet.h>

#include<postgresql/libpq-fe.h>


#define MAX_THREAD 3
#define MAX_TASKS 100

#define MAIN_PORT 10000

#define MAX_LISTEN 10



#define INA_SERVER "192.168.10.3"
#define PORT_TOKEN 6000
#define PORT_2FA 6001

// 成功 1、再試行待ち 2、接続終了 0 など
#define SEND_OK       1
#define SEND_RETRY    2
#define SEND_CLOSED   0

#define RECV_OK       1  // 正常にデータを受信した
#define RECV_RETRY    2  // EAGAINで再登録した
#define RECV_CLOSED   0  // 接続が切断された



#define SUCCESS_CODE "success"
#define ERROR_CODE "error_code"
#define FORMAT_ERROR "format_erroe"
#define AUTH_ERROR "auth_error"
#define CALL_CODE "call"
#define SERVER_ERROR "server_error"
#define NONE_NAME "noname"

//構造体宣言

typedef enum{
    USER_STATE_GET_EMAIL,
    USER_STATE_GET_PASSWORD,
    USER_STATE_BAD_PASSWORD,//パスワード検証失敗時ランラムな値がタイムアウトに入れられ、ペナルティと化す。
    USER_STATE_GET_2FA,
    USER_STATE_BAD_2FA,
    USER_STATE_ACS,
}user_state_t;

//各ユーザー用の構造体
typedef struct {
    int sock;
    time_t timeout;
    uint8_t try;
    uint8_t flag[2];
    char addr_2fa[8];//2faサーバーの答えが格納されてるアドレス。
    char user_email[256];
    char user_uuid[37];
    user_state_t state;
}user_info_t;

//タスク構造体
typedef struct {
    void (*task_function)(user_info_t*);
    user_info_t *arg;
}task_t;

//スレッドプール
typedef struct {
    pthread_t thread_id[MAX_THREAD];
    task_t task[MAX_TASKS];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t cond;
}thread_pool_t;

//socket pool
typedef struct {
    _Atomic uint8_t flag;
    int sock[8];
    struct sockaddr_in address;
}socket_pool_t;

//メモリプール
//今回は4096人対応するために2層までにしてある。
typedef struct{
    _Atomic uint64_t chank1;
    _Atomic uint64_t chank2[64];
    user_info_t memory[64][64];
}memory_pool_t;

typedef struct{
    _Atomic uint8_t chank;
    PGconn *conn[8];
}database_pool_t;


//エラーハンドリング

void error_handler(char *errorMessage);

__attribute__((noreturn))
void DieWithError(char *errorMessage);
void socket_error(int error_code);
void epoll_ctl_error(int error_code);
void connect_error(int error_code);

//プール系
//スレッドプール関係
void init_thread_pool(thread_pool_t *pool);
void add_task(thread_pool_t *pool,void (*function)(user_info_t*),user_info_t *arg);
void *thread_worker(void *arg);

//接続プール系
//socketプールではUDP以外使わない前提
void init_socket_pool(socket_pool_t *pool);
uint8_t allocate_socket(socket_pool_t *pool);//使っていいソケットの番号を返す
void release_socket(socket_pool_t *pool,uint8_t flag);

//データベース接続プール
void init_db_pool(database_pool_t *pool,const char *query);
void reconnection_db_pool(database_pool_t *pool,const char *query);
uint8_t allocate_db(database_pool_t *pool);//フラグ番号を返す。
void release_db(database_pool_t *pool,uint8_t flag);

//メモリプール
void init_memory_pool(memory_pool_t *pool);
user_info_t *allocate_memory(memory_pool_t *pool);
void release_memory(memory_pool_t *pool,user_info_t *info);

//システム関数
int set_nonblocking(int fd);
uint8_t send_to_user(user_info_t *info,char *buffer,size_t size);
uint8_t recv_from_user(user_info_t *info,char *buffer,size_t size);

//login system

void user_get_email(user_info_t *info);
void user_get_password(user_info_t *info);
void user_test_2fa(user_info_t *info);
void user_send_2fa(user_info_t *info);
void user_get_acs_token(user_info_t *info);
void user_get_rfs_token(user_info_t *info);
void close_user_socket(user_info_t *info);
void user_get_rfs_token(user_info_t *info);
void user_delete_2fa(user_info_t *info);
void reconection_db_pool(database_pool_t *pool,const char *query);

//グローバル変数

FILE *error_fp;
memory_pool_t user_memory_pool;
thread_pool_t thread_pools;
socket_pool_t pool_of_2fa;
socket_pool_t pool_of_token;
database_pool_t user_db_pool;
socklen_t addr_size=sizeof(struct sockaddr_in);

int epoll_fd;

int main(void){
    mlockall(MCL_CURRENT | MCL_FUTURE);
    //プール関係初期化
    const char *query_a="host=192.168.10.3 port=5432 user=postgres";
    init_memory_pool(&user_memory_pool);
    init_db_pool(&user_db_pool,query_a);
    init_thread_pool(&thread_pools);
    init_socket_pool(&pool_of_2fa);
    pool_of_2fa.address.sin_family=PF_INET;
    pool_of_2fa.address.sin_port=htons(PORT_2FA);
    if(__builtin_expect(inet_pton(PF_INET,INA_SERVER,&pool_of_2fa.address.sin_addr)==-1,0)){
        DieWithError("[inet_pton failed][pool_of_2fa]");
    }
    init_socket_pool(&pool_of_token);
    pool_of_token.address.sin_family=PF_INET;
    pool_of_token.address.sin_port=htons(PORT_TOKEN);
    if(__builtin_expect(inet_pton(PF_INET,INA_SERVER,&pool_of_token.address.sin_addr)==-1,0)){
        DieWithError("[inet_pton failed][pool_of_token]");
    }
    error_fp=fopen("error.log","wt");
    if(__builtin_expect(error_fp==NULL,0)){
        DieWithError("[fopen failed]");
    }
    //socket
    int sock=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
    if(__builtin_expect(sock==-1,0)){
        int error_code=errno;
        socket_error(error_code);
    }
    set_nonblocking(sock);
    struct sockaddr_in servAddr;
    memset(&servAddr,0,sizeof(servAddr));
    servAddr.sin_family=PF_INET;
    servAddr.sin_port=htons(MAIN_PORT);
    if(__builtin_expect(inet_pton(PF_INET,"0.0.0.0",&servAddr.sin_addr)!=1,0))DieWithError("[inet_pton failed]");
    bind(sock,(struct sockaddr*)&servAddr,(socklen_t)sizeof(servAddr));
    listen(sock,MAX_LISTEN);
    //epoll
    epoll_fd=epoll_create1(0);
    if(__builtin_expect(epoll_fd==-1,0)){
        int error_code=errno;
        switch(error_code){
            case EINVAL:
                DieWithError("[epoll_create1 failed][EINVAL:flagに無効な値が指定された。]");

            case EMFILE:
                DieWithError("[epoll_create1 failed][EMFILE:/proc/sys/fs/epoll/max_user_instancesによってい指定されているepollインスタンスのユーザー単位の制限い達した。]");

            case ENFILE:
                DieWithError("[epoll_create1 failed][ENFILE:システム全体で開かれているファイルの数野上限に達した。]");

            case ENOMEM:
                DieWithError("[epoll_create1 failed][ENOMEM:カーネルオブジェクト作成するのに十分なメモリーが無かった。]");

        }
    }
    struct epoll_event event;
    event.events=EPOLLET | EPOLLIN;//エッジトリガ
    event.data.fd=sock;
    if(__builtin_expect(epoll_ctl(epoll_fd,EPOLL_CTL_ADD,sock,&event)==-1,0)){
        int error_code=errno;
        epoll_ctl_error(error_code);
    }
    struct epoll_event ev[4096];
    for(;;){
        int ret=epoll_wait(epoll_fd,ev,4096,-1);
        for(int i = 0 ; i  < ret ; i ++){
            if(ev[i].data.fd==sock){
                user_info_t *info=allocate_memory(&user_memory_pool);
                info->sock=accept(sock,(struct sockaddr*)&servAddr,&addr_size);
                set_nonblocking(info->sock);
                struct epoll_event ev1;
                ev1.data.ptr=info;
                ev1.events=EPOLLET | EPOLLIN;
                if(__builtin_expect(epoll_ctl(epoll_fd,EPOLL_CTL_ADD,info->sock,&ev1)==-1,0)){
                    epoll_ctl_error(errno);
                }
                add_task(&thread_pools,user_get_email,info);
            }else{
                user_info_t *info=ev[i].data.ptr;
                switch(info->state){
                    case USER_STATE_GET_EMAIL:
                        add_task(&thread_pools,user_get_password,info);
                        break;
                    case USER_STATE_GET_PASSWORD:
                        add_task(&thread_pools,user_send_2fa,info);
                        break;
                    case USER_STATE_GET_2FA:
                        add_task(&thread_pools,user_get_acs_token,info);
                        break;
                    case USER_STATE_ACS:
                        add_task(&thread_pools,user_get_rfs_token,info);
                        break;
                    case USER_STATE_BAD_PASSWORD://BADシリーズ
                        if(__builtin_expect(info->timeout<time(NULL),1))add_task(&thread_pools,user_get_password,info);
                        break;
                    case USER_STATE_BAD_2FA:
                        if(__builtin_expect(info->timeout<time(NULL),1))add_task(&thread_pools,user_delete_2fa,info);
                        break;
                }
            }
        }
    }

}

void user_get_email(user_info_t *info) {
user_get_email_start_point:
    memset(info->user_email, 0, sizeof(info->user_email));
    switch (recv_from_user(info, info->user_email, sizeof(info->user_email) - 1)) {
        case SEND_OK: break;
        case SEND_RETRY: goto user_get_email_start_point;
        case SEND_CLOSED: return;
    }

    // ユーザーemailでUUID取得
    const char *query = "SELECT user_uuid FROM users WHERE user_email=$1";
    const char *paramValue[1] = { info->user_email };
    const int paramFormats[1] = { 0 };  // text format
    const int *paramLength = NULL;      // 無視される

    uint8_t flag = allocate_db(&user_db_pool);
    PGresult *res = PQexecParams(user_db_pool.conn[flag], query, 1, NULL, paramValue, paramLength, paramFormats, 0);

    if (__builtin_expect(res == NULL, 0)) {
        send_to_user(info, SERVER_ERROR, sizeof(SERVER_ERROR) - 1);
        goto user_get_email_end_point;
    }

    if (__builtin_expect(PQresultStatus(res) != PGRES_TUPLES_OK, 0)) {
        goto user_get_email_end_point;
    }

    if (__builtin_expect(PQntuples(res) != 1, 0)) {
        send_to_user(info,NONE_NAME,sizeof(NONE_NAME)-1);
        goto user_get_email_end_point;
    }

    char *uuid = PQgetvalue(res, 0, 0);
    __builtin_memcpy(info->user_uuid, uuid, 36);
    info->state=USER_STATE_GET_EMAIL;

user_get_email_end_point:
    if (res) PQclear(res);
    release_db(&user_db_pool, flag);
    return;
}


void user_get_password(user_info_t *info){
    //ユーザーから平文のパスワードを受信、
    //ユーザーから送られてきたパスワードを一瞬でargon2_idによりhash化する。
    //postgresqlからuser uuidによりパスワードハッシュを検索 
    //__builtin_memcmp()によりハッシュを称号する。
    //成功すればSUCCESS_CODEを返し失敗したらAUTH_ERRORを返す。
    //return;
    //timeoutペナルティとして50s間のロック stateにUSER_STATE_BAD_PASSWORDを設定
user_get_password_start_point:
    (void)0;
    char user_password[1024];
    memset(user_password,0,sizeof(user_password));
    switch(recv_from_user(info,user_password,1022)){
        case RECV_OK:
            break;
        case RECV_RETRY:
            goto user_get_password_start_point;
        case RECV_CLOSED:
            return;
    }
    user_password[1023]='\0';
    const char *query="SELECT password_hash,salt FROM users WHERE user_id=$1";
    const char *paramValue[1]={info->user_uuid};
    const int paramLength[1]={36};
    const int paramFormats[1]={0};
    char hash[64];
user_get_password_start_point1:
    (void)0;
    uint8_t flag=allocate_db(&user_db_pool);
    PGresult *res=PQexecParams(user_db_pool.conn[flag],query,1,NULL,paramValue,paramLength,paramFormats,0);
    if(__builtin_expect(res==NULL,0)){
        release_db(&user_db_pool,flag);
        send_to_user(info,SERVER_ERROR,sizeof(SERVER_ERROR)-1);
        return;
    }
    if(__builtin_expect(PQresultStatus(res)!=PGRES_TUPLES_OK,0)){
        //error handling
        error_handler("[user_get_password][PQexecParams failed]");
        goto user_get_password_start_point1;
    }
    char *password_hash=PQgetvalue(res,0,0);
    char *salt=PQgetvalue(res,0,1);
    int salt_len=PQgetlength(res,0,1);
    argon2id_hash_raw(
        3,//t_cost(反復回数)
        1<<16,//64MiB,
        1,//並列度
        user_password,strlen(user_password),
        (uint8_t*)salt,(size_t)salt_len,
        hash,sizeof(hash)
    );
    PQclear(res);
    release_db(&user_db_pool,flag);
    if(__builtin_expect(__builtin_memcmp(password_hash,&hash,sizeof(hash))!=0,0)){
        info->state=USER_STATE_BAD_PASSWORD;
        info->timeout=time(NULL)+50;
user_get_password_point2:
        if(__builtin_expect(send_to_user(info,AUTH_ERROR,sizeof(AUTH_ERROR)-1)==SEND_RETRY,0)){
            goto user_get_password_point2;
        }
    }else{
        info->state=USER_STATE_GET_PASSWORD;
user_get_password_point3:
        if(__builtin_expect(send_to_user(info,SUCCESS_CODE,sizeof(SUCCESS_CODE))==SEND_RETRY,0)){
            goto user_get_password_point3;
        }
    }
    return;
}

void user_delete_2fa(user_info_t *info){
    char buffer[10];
    memset(buffer,0,sizeof(buffer));
    snprintf(buffer,9,"%sD",info->addr_2fa);
    uint8_t flag=allocate_socket(&pool_of_2fa);
    if(__builtin_expect(send(pool_of_2fa.sock[flag],buffer,9,0)==-1,0)){
        release_socket(&pool_of_2fa,flag);
        send_to_user(info,SERVER_ERROR,sizeof(SERVER_ERROR)-1);
        return ;
    }
    add_task(&thread_pools,user_send_2fa,info);
    return;
}

void user_send_2fa(user_info_t *info){
    //はねかえすのはイベント駆動で実行
    //相手からcallが送られてきた
    //2faサーバーにリクエスト。
    //emailを送信
    //uintptr_tを返してくる。
    //user_info_tに格納
    char buffer[sizeof(CALL_CODE)];
    memset(buffer,0,sizeof(CALL_CODE));
    if(__builtin_expect(recv_from_user(info,buffer,sizeof(SUCCESS_CODE)-1)!=RECV_OK,0))return;
    //2faサーバーにリクエスト
    uint8_t flag=allocate_socket(&pool_of_2fa);
user_send_2fa_start_point:
    if(__builtin_expect(send(pool_of_2fa.sock[flag],CALL_CODE,sizeof(CALL_CODE)-1,0)==-1,0)){
        switch(errno){
            case EAGAIN:
                goto user_send_2fa_start_point;
            case ENOBUFS:
                error_handler("[user_send_2fa][send failed][ENOBUFS:システムリソースが枯渇しています。]");
                goto user_send_2fa_start_point;
            default:
                DieWithError("[user_send_2fa][send failed][設計ミスか致命的なエラー]");
        }
    }
user_send_2fa_point2:
    if(__builtin_expect(recv(pool_of_2fa.sock[flag],info->addr_2fa,8,0)==-1,0)){
        switch(errno){
            case EAGAIN:
                goto user_send_2fa_point2;
            case ENOBUFS:
                error_handler("[user_send_2fa][send failed][ENOBUFS:システムリソースが枯渇しています。]");
                goto user_send_2fa_point2;
            default:
                DieWithError("[user_send_2fa][send failed][設計ミスか致命的なエラー]");
        }
    }
    release_socket(&pool_of_2fa,flag);
    //ユーザーにSUCCESS_CODEを送信
    if(__builtin_expect(send_to_user(info,SUCCESS_CODE,sizeof(SUCCESS_CODE)-1)==SEND_OK,1)){
        info->state=USER_STATE_GET_2FA;
        return;
    }
    return;
}

void user_test_2fa(user_info_t *info){
    char buffer[7];//6桁の数字とアドレス（コードの場所）
    memset(buffer,0,sizeof(buffer));
    //ユーザーから受け取る
user_test_2fa_start_point:
    switch(recv_from_user(info,buffer,6)){
        case SEND_OK:
            break;
        case SEND_RETRY:
            goto user_test_2fa_start_point;
        case SEND_CLOSED:
            close_user_socket(info);
            return;
    }
    uint8_t flag=allocate_socket(&pool_of_2fa);
user_test_2fa_point1:
    (void)0;
    char sendbuffer[6+8+1];
    memset(sendbuffer,0,sizeof(sendbuffer));
    snprintf(sendbuffer,sizeof(sendbuffer),"%s%s",info->addr_2fa,buffer);
    if(__builtin_expect(send(pool_of_2fa.sock[flag],sendbuffer,sizeof(sendbuffer)-1,0)==-1,0)){
        switch(errno){
            case EAGAIN:
                goto user_test_2fa_point1;
            case ENOBUFS:
                error_handler("[user_test_2fa][send failed][ENOBUFS:カーネルに十分なバッファがない場合。システム全体のリソースが枯渇している可能性あり。]");
                goto user_test_2fa_point1;
            default:
                DieWithError("[user_test_2fa][設計ミスか致命的エラー]");
        }
    }
user_test_2fa_point2:
    memset(buffer,0,sizeof(buffer));
    if(__builtin_expect(recv(pool_of_2fa.sock[flag],buffer,1,0)==-1,0)){
        switch(errno){
            case EAGAIN:
                goto user_test_2fa_point2;
            case ENOBUFS:
                error_handler("[user_test_2fa][send failed][ENOBUFS:一時的リソース不足、]");
                goto user_test_2fa_point2;
            default:
                DieWithError("[user_test_2fa][send failed][設計ミスか致命的エラー]");
        }
    }
    release_socket(&pool_of_2fa,flag);
    if(__builtin_expect(buffer[0]==48,0)){
        send_to_user(info,SUCCESS_CODE,sizeof(SUCCESS_CODE)-1);
        info->timeout=0;
        add_task(&thread_pools,user_get_acs_token,info);
    }else{
        send_to_user(info,AUTH_ERROR,sizeof(AUTH_ERROR)-1);
        //タイムアウト設定
        if(__builtin_expect(++info->try<=3,0)){
            info->timeout=time(NULL)+30;
        }
        info->state=USER_STATE_BAD_2FA;
    }
    return;
}

void user_get_rfs_token(user_info_t *info){
        //Ed25519の署名は64byte固定
    char buffer[3+1+36+1+64+1];//acs|user_uuid|token_uuid|署名NULL(このbufferは使い回す)
    memset(buffer,0,sizeof(buffer));
    if(__builtin_expect(recv_from_user(info,buffer,sizeof(SUCCESS_CODE))!=RECV_OK,0))return;
    if(__builtin_expect(__builtin_memcmp(buffer,SUCCESS_CODE,sizeof(SUCCESS_CODE)-1)!=0,1)){
        close_user_socket(info);
        return;
    }
    snprintf(buffer,41,"rfs|%s",info->user_uuid);
    uint8_t flag=allocate_socket(&pool_of_token);
user_get_rfs_token_point1:
    if(__builtin_expect(send(pool_of_token.sock[flag],buffer,40,0)==-1,0)){
        switch(errno){
            case EAGAIN:
                goto user_get_rfs_token_point1;
            case ENOBUFS:
                error_handler("[user_get_rfs_token][send failed][ENOBUFS:カーネルに十分なバッファがない場合。システム全体のリソースが枯渇している可能性あり。]");
                goto user_get_rfs_token_point1;
            default:
                DieWithError("[user_get_rfs_token][send failed][たぶん設計ミスか致命的エラー]");
        }
    }
user_get_rfs_token_point2:
    memset(buffer,0,sizeof(buffer));
    if(__builtin_expect(recv(pool_of_token.sock[flag],buffer,sizeof(buffer)-1,0)==-1,0)){
        switch(errno){
            case EAGAIN:
                goto user_get_rfs_token_point2;
            case ENOBUFS:
                error_handler("[user_get_rfs_token][recv failed][ENOBUFS:カーネルに十分なバッファがない場合。システム全体のリソースが枯渇している可能性あり。]");
                goto user_get_rfs_token_point2;
            default:
                DieWithError("[user_get_rfs_token][recv failed][たぶん設計ミスか致命的エラー]");
        }
    }
    release_socket(&pool_of_2fa,flag);
user_get_rfs_token_point3:
    if(__builtin_expect(send_to_user(info,buffer,sizeof(buffer)-1)==SEND_RETRY,0))goto user_get_rfs_token_point3;
    close_user_socket(info);
    return;
}

void user_get_acs_token(user_info_t *info){
    //Ed25519の署名は64byte固定
    char buffer[3+1+36+1+64+1];//acs|user_uuid|token_uuid|署名NULL(このbufferは使い回す)
    memset(buffer,0,sizeof(buffer));
    if(__builtin_expect(recv_from_user(info,buffer,sizeof(SUCCESS_CODE))!=RECV_OK,0))return;
    if(__builtin_expect(__builtin_memcmp(buffer,SUCCESS_CODE,sizeof(SUCCESS_CODE)-1)!=0,1)){
        close_user_socket(info);
        return;
    }
    snprintf(buffer,41,"acs|%s",info->user_uuid);
    uint8_t flag=allocate_socket(&pool_of_token);
user_get_acs_token_point1:
    if(__builtin_expect(send(pool_of_token.sock[flag],buffer,40,0)==-1,0)){
        switch(errno){
            case EAGAIN:
                goto user_get_acs_token_point1;
            case ENOBUFS:
                error_handler("[user_get_acs_token][send failed][ENOBUFS:カーネルに十分なバッファがない場合。システム全体のリソースが枯渇している可能性あり。]");
                goto user_get_acs_token_point1;
            default:
                DieWithError("[user_get_acs_token][send failed][たぶん設計ミスか致命的エラー]");
        }
    }
user_get_acs_token_point2:
    memset(buffer,0,sizeof(buffer));
    if(__builtin_expect(recv(pool_of_token.sock[flag],buffer,sizeof(buffer)-1,0)==-1,0)){
        switch(errno){
            case EAGAIN:
                goto user_get_acs_token_point2;
            case ENOBUFS:
                error_handler("[user_get_acs_token][recv failed][ENOBUFS:カーネルに十分なバッファがない場合。システム全体のリソースが枯渇している可能性あり。]");
                goto user_get_acs_token_point2;
            default:
                DieWithError("[user_get_acs_token][recv failed][たぶん設計ミスか致命的エラー]");
        }
    }
    release_socket(&pool_of_2fa,flag);
user_get_acs_token_point3:
    (void)0;
    uint8_t ret=send_to_user(info,buffer,sizeof(buffer)-1);
    if(__builtin_expect(ret==SEND_OK,0)){
        add_task(&thread_pools,user_get_rfs_token,info);
    }else if(__builtin_expect(ret==SEND_RETRY,0)){
        goto user_get_acs_token_point3;
    }
    return;
}

void close_user_socket(user_info_t *info){
    if(__builtin_expect(epoll_ctl(epoll_fd,EPOLL_CTL_DEL,info->sock,NULL)==-1,0)){
        int error_code=errno;
        switch(error_code){
            case EBADF:
                //fdぶっ壊れてる
                goto close_user_socket_end_point;
            case ENOENT:
                //登録されていなかった（謎w）
                goto close_user_socket_end_point;
            default:
                //一応ログだけ取って置く
                error_handler("[close_user_socket][epoll_ctl failed]");
        }
    }
    if(__builtin_expect(close(info->sock)==-1,0)){
        if(__builtin_expect(errno==EIO,0)){
            DieWithError("[close_user_socket][close failed][EIO:悪魔のエラー]");
        }
    }
close_user_socket_end_point:
    release_memory(&user_memory_pool,info);
    return;
}

void init_memory_pool(memory_pool_t *pool){
    memset(pool,0,sizeof(memory_pool_t));
    return;
}

user_info_t *allocate_memory(memory_pool_t *pool){
    uint8_t flag[2];
search_chank1_flag:
    flag[0]=(uint8_t)__builtin_ctzll(~atomic_load(&pool->chank1));
    if(__builtin_expect(flag[0]==64,0))return NULL;
    flag[1]=(uint8_t)__builtin_ctzll(~atomic_load(&pool->chank2[flag[0]]));
    if(__builtin_expect(flag[1]==64,0))goto search_chank1_flag;
    atomic_fetch_and(&pool->chank2[flag[0]],1ULL<<flag[1]);
    if(__builtin_expect(pool->chank2[flag[0]]==UINT64_MAX,0))atomic_fetch_and(&pool->chank1,1ULL<<flag[0]);
    return &pool->memory[flag[0]][flag[1]];
}

void release_memory(memory_pool_t *pool,user_info_t *info){
    atomic_fetch_and(&pool->chank2[info->flag[0]],~(1ULL<<info->flag[1]));
    atomic_fetch_and(&pool->chank1,~(1ULL<<info->flag[0]));
    memset(&pool->memory[info->flag[0]][info->flag[1]],0,sizeof(user_info_t));
    return;
}

void reconnection_db_pool(database_pool_t *pool,const char *query){
    pool->chank=0;
    for(uint8_t i =0;i<8;i++){
        if(__builtin_expect(pool->conn[i]!=CONNECTION_OK,0)){
            pool->conn[i]=PQconnectdb(query);
            if(__builtin_expect(pool->conn[i]!=CONNECTION_OK,0))atomic_fetch_and(&pool->chank,1ULL<<i);
        }
    }
    if(__builtin_expect(__builtin_popcount((unsigned int)(pool->chank))>=3,0)){
        DieWithError("[init_db_pool failed][connection try failed count 3 over]");
    }
    return;
}

void init_db_pool(database_pool_t *pool,const char *query){
    pool->chank=0;
    for(uint8_t i = 0; i < 8; i++){
        pool->conn[i]=PQconnectdb(query);
        if(__builtin_expect(pool->conn[i]!=CONNECTION_OK,0)){
            error_handler("[PQconnectdb failed][CONNECT_BAD]");
            atomic_fetch_or(&pool->chank,1ULL<<i);
        }
    }
    if(__builtin_expect(__builtin_popcount((unsigned int)(pool->chank))>=3,0)){
        DieWithError("[init_db_pool failed][connection try failed count 3 over]");
    }
    return;
}

uint8_t allocate_db(database_pool_t *pool){
    uint8_t flag=(uint8_t)__builtin_ctz(~atomic_load(&pool->chank));
    atomic_fetch_or(&pool->chank,1ULL<<flag);
    if(__builtin_expect(flag==0,0)){
        const char *query_a="host=192.168.10.3 port=5432 user=postgres";
        reconnection_db_pool(pool,query_a);
        return allocate_db(pool);
    }
    return flag;
}

void release_db(database_pool_t *pool,uint8_t flag){
    atomic_fetch_and(&pool->chank,~(1<<flag));
}

void init_socket_pool(socket_pool_t *pool){
    uint8_t count=0;
    pool->flag=0;
    for(uint8_t i=0;i<8;i++){
        int ret=close(pool->sock[i]);
        if(__builtin_expect(ret==-1,0)){
            int error_code=errno;
            switch(error_code){
                case EBADF:
                    break;
                case EINTR:
                    i--;
                    break;
                case EIO:
                    atomic_fetch_or(&pool->flag,1ULL<<i);
                    count++;
                    if(__builtin_expect(count>3,0))DieWithError("[init_socket_pool][close fialed][EIO:I/Oエラーが発生しました。]");
                    break;
            }
        }
    }
    pool->flag=0;
    for(int i=0;i<8;i++){
        pool->sock[i]=socket(PF_INET,SOCK_STREAM,IPPROTO_TCP);
        if(__builtin_expect(pool->sock[i]<=0,0)){
            socket_error(errno);
        }//ここでエラーが起きたらプロセスを再起動
        if(__builtin_expect(connect(pool->sock[i],(struct sockaddr*)&pool->address,(socklen_t)sizeof(pool->address))==-1,0)){
            connect_error(errno);
        }
    }
    return ;
}

uint8_t allocate_socket(socket_pool_t *pool){
    uint8_t flag=(uint8_t)__builtin_ctz((unsigned int)~atomic_load(&pool->flag));
    atomic_fetch_or(&pool->flag,1ULL << flag);
    if(__builtin_expect(flag==0,0)){
        error_handler("[allocate_socket][socket pool on none socket]");
        init_socket_pool(pool);
    }
    return flag;
}

void release_socket(socket_pool_t *pool,uint8_t flag){
    atomic_fetch_and(&pool->flag,~(1ULL << flag));
    return ;
}

void error_handler(char *errorMessage){
    fputs(errorMessage,error_fp);
    return ;
}

__attribute__((noreturn))
void DieWithError(char *errorMessage){
    FILE *fp;
    fp=fopen("backup.bin","wb");
    fwrite((char*)&user_memory_pool, sizeof(user_memory_pool), 1, fp);
    fclose(fp);
    error_handler(errorMessage);
    exit(EXIT_FAILURE);
}

void init_thread_pool(thread_pool_t *pool){
    pthread_mutex_init(&pool->mutex,NULL);
    pthread_cond_init(&pool->cond,NULL);
    pthread_mutex_lock(&pool->mutex);
    for(uint8_t i = 0;i<MAX_THREAD;i++){
        int ret=pthread_create(&pool->thread_id[i],NULL,&thread_worker,&pool);
        if(__builtin_expect(ret!=0,0)){
                DieWithError("[pthread_create failed][EAGAIN:別のスレッドを作成するのに十分ないソースじゃない。]");
        }
    }
    pool->head=0;
    pool->tail=0;
    pool->count=MAX_THREAD;
    pthread_mutex_unlock(&pool->mutex);
    return;
}

void add_task(thread_pool_t *pool,void (*task_function)(user_info_t*),user_info_t *arg){
    pthread_mutex_lock(&pool->mutex);
    if(__builtin_expect(pool->count>=MAX_TASKS,0)){
        printf("Task queue is full!\n");
        pthread_mutex_unlock(&pool->mutex);
        return;
    }
    pool->task[pool->tail].task_function=task_function;
    pool->task[pool->tail].arg=arg;
    pool->tail=(pool->tail+1)%MAX_TASKS;
    pool->count++;
    pthread_cond_signal(&pool->cond);
    pthread_mutex_unlock(&pool->mutex);
}

void *thread_worker(void *arg){
    thread_pool_t *pool=(thread_pool_t *)arg;
    for(;;){
        pthread_mutex_lock(&pool->mutex);
        //タスクがない場合は待機
        while(pool->count==0)pthread_cond_wait(&pool->cond,&pool->mutex);

        //タスクを先頭から取り出す
        task_t task=pool->task[pool->head];
        pool->head=(pool->head+1)%MAX_TASKS;
        pool->count--;
        pthread_mutex_unlock(&pool->mutex);
        //タスク実行
        task.task_function(task.arg);
    }
    __builtin_unreachable();
}

uint8_t send_to_user(user_info_t *info,char *buffer,size_t size){
send_to_user_start_point1:
    (void)0;
    if(__builtin_expect(send(info->sock,buffer,size,0)==-1,0)){
        switch(errno){
            case EAGAIN://linuxではEWOULBLOCKはEAGAINと同じ
                (void)0;
                struct epoll_event event;
                event.data.ptr=info;
                event.events=EPOLLET|EPOLLOUT;
                if(__builtin_expect(epoll_ctl(epoll_fd,EPOLL_CTL_MOD,info->sock,&event)==-1,0)){
                    int error_code=errno;
                    epoll_ctl_error(error_code);
                }
                return SEND_RETRY;
            case EPIPE:
                error_handler("[send_to_user][EPIPE:相手がclose()済み]");
                close_user_socket(info);
                return SEND_CLOSED;
            case ECONNRESET:
                error_handler("[send_to_user][ECONNRESET:相手がRstパケットを送ってきやがった（相手からの強制切断）]");
                close_user_socket(info);
                return SEND_CLOSED;
            case EINTR:
                goto send_to_user_start_point1;
            case ENOTCONN:
                DieWithError("[send_to_user][設計ミスしたお前のせい☆][ENOTCONN:acceptの前にsendした]");

            case EINVAL:
                DieWithError("[send_to_user][設計見直ししろ、お前のせい☆][EINVAL:不正なサイズ、フラグ、状態]");

            case EBADF:
                close_user_socket(info);
                return SEND_CLOSED;
            case ENOTSOCK:
                DieWithError("[send_to_user][設計不良ﾊｰﾄ][ENOTSOCK:そのfdソケットじゃねぇしw]");

            case EFAULT:
                DieWithError("[send_to_user][send failed][bufが壊れてる]");

            case EIO:
                DieWithError("[send_to_user][send failed][EIO:悪魔のエラー、I/Oぶっ壊れました]");

            case EACCES:
                DieWithError("[send_to_user][send failed][EACCESS:権限なし]");

            case ENOBUFS:
                DieWithError("[send_to_user][send failed][ENOBUFS:システムのバッファが不足してます。]");

            case ENOMEM:
                DieWithError("[send_to_user][send failed][ENOMEM:メモリ不足により、送信捜査が実行できない場合に発生します。]");

            default:
                error_handler("[send_to_user][send failed][etc_error]");
        }
    }
    return SEND_OK;
}

uint8_t recv_from_user(user_info_t *info, char *buffer, size_t size) {
recv_from_user_start_point1:
    (void)0;
    ssize_t ret = recv(info->sock, buffer, size, 0);
    if (__builtin_expect(ret == -1, 0)) {
        int err = errno;
        switch (err) {
            case EAGAIN: {
                struct epoll_event event;
                event.data.ptr = info;
                event.events = EPOLLET | EPOLLIN;
                if (__builtin_expect(epoll_ctl(epoll_fd, EPOLL_CTL_MOD, info->sock, &event) == -1, 0)) {
                    epoll_ctl_error(errno);
                }
                return RECV_RETRY; // EAGAINなら再登録してリトライ
            }
            case ECONNRESET:
                error_handler("[recv_from_user][ECONNRESET:相手からRstパケットが送られた（相手が強制切断）]");
                close_user_socket(info);
                return RECV_CLOSED;
            case EPIPE:
                error_handler("[recv_from_user][EPIPE:相手が接続を閉じた]");
                close_user_socket(info);
                return RECV_CLOSED;
            case EINTR:
                goto recv_from_user_start_point1; // シグナル処理による中断
            case ENOTCONN:
                DieWithError("[recv_from_user][設計ミス:acceptの前にrecvが呼ばれた]");

            case EINVAL:
                DieWithError("[recv_from_user][設計見直し:不正な引数]");

            case EBADF:
                close_user_socket(info);
                return RECV_CLOSED;
            case ENOTSOCK:
                DieWithError("[recv_from_user][設計ミス:そのfdソケットじゃねぇしw]");

            case EFAULT:
                DieWithError("[recv_from_user][recv failed][バッファ破損]");

            case EIO:
                DieWithError("[recv_from_user][recv failed][I/Oエラー]");

            case EACCES:
                DieWithError("[recv_from_user][recv failed][権限なし]");

            case ENOBUFS:
                DieWithError("[recv_from_user][recv failed][バッファ不足]");

            case ENOMEM:
                DieWithError("[recv_from_user][recv failed][メモリ不足]");

            default:
                error_handler("[recv_from_user][recv failed][未知エラー]");
        }
    }
    return RECV_OK;
}


void socket_error(int error_code){
    switch(error_code){
        case EACCES:
            DieWithError("[socket failed][EACCES:指定されたタイプ又はプロトコルのソケットを作成する許可が与えられていない。]");
        case EAFNOSUPPORT:
            DieWithError("[socket failed][EAFNOSUPPORT:指定されたアドレスファミルーあサポートされていない。]");
        case EINVAL:
            DieWithError("[socket failed][EINVAL:知らないプロトコル、又は利用できないプロ五個るファミリーである。]");
        case EMFILE:
            DieWithError("[socket failed][EMFILE:1プロセスがオープンできるファイルディスクリプタの上限数に達した。]");
        case ENFILE:
            DieWithError("[socket failed][ENFILE:オープンされたファイルの総数がシステム全体の上限に達した。]");
        case ENOBUFS:
            DieWithError("[socket failed][ENOBUFS:十分なメモリーがない。]");
        case ENOMEM:
            DieWithError("[socket failed][ENOMEM:っ十分な資源が解放されるまではソケットを作成することは出来ない。]");
        case EPROTONOSUPPORT:
            DieWithError("[socket failed][EPROTONOSUPPORT:このドメインでは指定されたプロトコル又はプロトコルタイプがサポートされていない。]");
    }
}

void epoll_ctl_error(int error_code){
    switch(error_code){
        case EBADF:
            DieWithError("[epoll_ctl failed][EBADF:epfdかfdが有効なファイルディスクリプターではない。]");
        case EEXIST:
            DieWithError("[epoll_ctl failed][EEXIST:opがEPOLL_CTL_ADDであり、かつ与えられたファイルディスクリプターfdがこのepollインスタンスに既に登録されている。]");
        case EINVAL:
            DieWithError("[epoll_ctl failed][EINVAL:epfdがepollファイルディスクリプターでない。又はfdがepfdと同一である。又は要求された走査opがこのインターフェースでサポートされていない。]");
        case ENOENT:
            DieWithError("[epoll_ctl failed][ENOENT:opがEPOLL_CTL_MOD又はEPOLL_CTL_DELで、かつfdがこのepollインスタンスに登録されていない。]");
        case ENOMEM:
            DieWithError("[epoll_ctl failed][ENOMEM:要求されたop制御捜査を扱うのに十分なメモリーがない。]");
        case ENOSPC:
            DieWithError("[epoll_ctl failed][ENOSPC:epollインスタンスに新しいファイルディスクリプターを登録しようとした際に、/proc/sys/fs/epoll/max_user_watchesで極る上限に達した。]");
        case EPERM:
            DieWithError("[epoll_ctl failed][EPERM:対象fdがepollに対応していない。このエラーはfdが例えば通常ファイルやディレクトリを参照している場合にも起り得る。]");
    }
}

void connect_error(int error_code){
    switch(error_code){
        case EACCES:
            DieWithError("[connect_error][EACCES:UNIXドメインソケットはパス名で識別される。ソケットファイルへの書き込み許可がなかったか、パス名へ到達するまでのディれくトリのいずれかに対する検索許可がなかった。]");
        case EPERM:
            DieWithError("[connect_error][EPERM:ローカルのファイアウォールの規則により接続の要求が失敗した。]");
        case EADDRINUSE:
            DieWithError("[connect_error][EADDRINUSE:ローカルアドレスが既に使用されています。]");
        case EADDRNOTAVAIL:
            DieWithError("[connect_error][EADDRNOTAVAIL:(インターネットドメインソケットの場合) sockfd が参照するソケットがそれ以前にアドレスにバインドされておらず、  そのソケットに一時ポートをバインドしようとした際に、  一時ポートとして使用する範囲のポート番号がすべて使用中であった。]");
        case EAFNOSUPPORT:
            DieWithError("[connect_error][EAFNOSUPPORT:渡されたアドレスのsa_familyフィールドが正しいアドレスファミリーではない。]");
        case EAGAIN:
            DieWithError("[connect_error][EAGAIN:それ以外のソケットファミリーでは、ルーティングキャッシュに十分なエントリがない（つまり経路情報が揃ってない）ために失敗した。]");
        case EALREADY:
            DieWithError("[connect_error][EALREADY:ソケットが非停止 (nonblocking) に設定されており、 前の接続が完了していない。]");
        case EBADF:
            error_handler("[connect_error][EBADF:ソケットが有効なファイルディスクり二ではない。]");
            return;
        case ECONNREFUSED:
            DieWithError("[connect_error][ECONNREFUSED:非同期ソケットならこのエラーアリエルよね。]");
        case EINTR:
            error_handler("[connect_error][EINTR:捕捉されたシグナルによりシステムコールが中断された。]");
            return;
        case EISCONN:
            error_handler("[connect_error][EISCONN:ソケットは既に接続されている。]");
            return;
        case ENETUNREACH:
            DieWithError("[connect_error][ENETUNREACH:到達できないネットワークである。]");
        case ENOTSOCK:
            error_handler("[connect_error][ENOTSOCK:ファイルディスクリプターがsockfdをがソケットを参照していない。]");
            return;
        case EPROTOTYPE:
            DieWithError("[connect_error][EPROTOTYPE:ソケットタイプが要求された通信プロトコルではサポートされていない。このエラーは、  例えば UNIX ドメインデータグラムソケットをストリームソケットに接続しようとした場合などに起こり得る。]");
        case ETIMEDOUT:
            DieWithError("[connect_error][ETIMEDOUT: 接続を試みている途中で時間切れ (timeout)  になった。サーバーが混雑していて  新たな接続を受け入れられないのかもしれない。 IP ソケットでは、 syncookie がサーバーで有効になっている場合、 タイムアウトが非常に長くなる場合があるので注意すること。]");
        default:
            __builtin_unreachable();
   }
}

int set_nonblocking(int fd) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return -1;
    return fcntl(fd, F_SETFL, flags | O_NONBLOCK);
}