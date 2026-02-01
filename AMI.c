                                            /* HERE WE GO...*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <locale.h>

/* Configuration portable */
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <conio.h>
    #include <process.h>
    #pragma comment(lib, "ws2_32.lib")
    #define close closesocket
    #define sleep(seconds) Sleep((seconds) * 1000)
    #define CLEAR_SCREEN "cls"
    #define pthread_t HANDLE
    #define pthread_create(thr, attr, func, arg) \
        (*thr = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)func, arg, 0, NULL), \
         (*thr != NULL) ? 0 : -1)
    #define pthread_join(thr, status) WaitForSingleObject(thr, INFINITE)
    #define pthread_detach(thr) CloseHandle(thr)
    #define pthread_mutex_t CRITICAL_SECTION
    #define pthread_mutex_init(mutex, attr) InitializeCriticalSection(mutex)
    #define pthread_mutex_lock(mutex) EnterCriticalSection(mutex)
    #define pthread_mutex_unlock(mutex) LeaveCriticalSection(mutex)
    #define pthread_mutex_destroy(mutex) DeleteCriticalSection(mutex)
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <sys/select.h>
    #include <termios.h>
    #include <fcntl.h>
    #include <errno.h>
    #include <signal.h>
    #include <pthread.h>
    #define SOCKET int
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR (-1)
    #define sleep(seconds) usleep((seconds) * 1000000)
    #define CLEAR_SCREEN "clear"
#endif

/* SQLite - INCLURE LE FICHIER sqlite3.h */
#include "sqlite3.h"

/* Constantes de configuration */
#define MULTICAST_GROUP "224.0.0.1"
#define MULTICAST_PORT 8888
#define MAX_BUFFER_SIZE 1024
#define MAX_USERNAME 32
#define MAX_MESSAGE 900
#define MAX_USERS 100
#define HEARTBEAT_INTERVAL 5
#define USER_TIMEOUT 30 

/* CODES COULEUR */
#define COLOR_RESET   "\033[0m"
#define COLOR_RED     "\033[38;5;196m"
#define COLOR_GREEN   "\033[38;5;46m"
#define COLOR_YELLOW  "\033[38;5;226m"
#define COLOR_BLUE    "\033[38;5;33m"
#define COLOR_MAGENTA "\033[38;5;201m"
#define COLOR_CYAN    "\033[38;5;51m"
#define COLOR_ORANGE  "\033[38;5;208m"
#define COLOR_PINK    "\033[38;5;213m"
#define COLOR_BOLD    "\033[1m"

/* Structures de données */
typedef struct {
    char username[MAX_USERNAME];
    char ip[16];
    time_t last_seen;
    int is_online;
} UserInfo;

typedef struct {
    char username[MAX_USERNAME];
    char channel[32];
    SOCKET sock;
    struct sockaddr_in multicast_addr;
    UserInfo users[MAX_USERS];
    int user_count;
    sqlite3 *history_db;
    int running;
    int silent_mode;
    pthread_mutex_t db_mutex;
} ChatSession;

/* Variables globales */

void cleanup_and_exit(ChatSession* session);
void print_colored_username(const char* username);
int count_online_users(ChatSession* session);

ChatSession* global_session_ptr = NULL;
static int prompt_displayed = 0;

//Ajout
static char input_buffer[MAX_MESSAGE];
static int input_pos = 0;
#ifdef _WIN32
    //volatile int exit_flag = 0;
#else
    volatile sig_atomic_t exit_flag = 0;
#endif

/* ==================== GESTION DES SIGNAUX ==================== */
#ifdef _WIN32
BOOL WINAPI console_handler(DWORD signal) {
    if (signal == CTRL_C_EVENT || signal == CTRL_CLOSE_EVENT) {
        if (global_session_ptr) {
            printf(COLOR_ORANGE "\n\n[!] Fermeture detectée. Déconnexion..." COLOR_RESET "\n");
            cleanup_and_exit(global_session_ptr);
        }
        return TRUE;
    }
    return FALSE;
}
#else
void signal_handler(int sig) {
    exit_flag = 1;
}
#endif

/* ==================== FONCTIONS SQLITE ==================== */

/* Initialise la base de données SQLite */
int init_sqlite_database(ChatSession *session) {
    char db_filename[256];
    snprintf(db_filename, sizeof(db_filename), "chat_%s.db", session->username);
    
    int rc = sqlite3_open(db_filename, &session->history_db);
    if (rc != SQLITE_OK) {
        fprintf(stderr, COLOR_RED "[!] Impossible d'ouvrir la base : %s\n" COLOR_RESET,
                sqlite3_errmsg(session->history_db));
        session->history_db = NULL;
        return 0;
    }
    
    /* Création de la table messages */
    const char *sql = 
        "CREATE TABLE IF NOT EXISTS messages("
        "id INTEGER PRIMARY KEY AUTOINCREMENT,"
        "timestamp TEXT NOT NULL,"
        "sender TEXT NOT NULL,"
        "recipient TEXT NOT NULL,"
        "type TEXT NOT NULL,"
        "content TEXT NOT NULL);"
        "CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp DESC);"
        "CREATE INDEX IF NOT EXISTS idx_sender ON messages(sender);"
        "CREATE INDEX IF NOT EXISTS idx_search ON messages(content);";
    
    char *err_msg = NULL;
    rc = sqlite3_exec(session->history_db, sql, 0, 0, &err_msg);
    
    if (rc != SQLITE_OK) {
        fprintf(stderr, COLOR_RED "[!] Erreur création table : %s\n" COLOR_RESET, err_msg);
        sqlite3_free(err_msg);
        sqlite3_close(session->history_db);
        session->history_db = NULL;
        return 0;
    }
    
    printf(COLOR_GREEN "[✓] Base de données initialisée : %s\n" COLOR_RESET, db_filename);
    return 1;
}

/* Ferme proprement la base de données */
void close_sqlite_database(ChatSession *session) {
    if (session->history_db) {
        sqlite3_close(session->history_db);
        session->history_db = NULL;
    }
}

/* Sauvegarde un message dans la base (thread-safe) */
void save_message_to_db(ChatSession *session, const char *timestamp, 
                       const char *sender, const char *recipient, 
                       const char *type, const char *content) {
    
    pthread_mutex_lock(&session->db_mutex);
    
    if (!session->history_db) {
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = "INSERT INTO messages (timestamp, sender, recipient, type, content) "
                      "VALUES (?, ?, ?, ?, ?);";
    
    if (sqlite3_prepare_v2(session->history_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    sqlite3_bind_text(stmt, 1, timestamp, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, sender, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, recipient, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 4, type, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 5, content, -1, SQLITE_STATIC);
    
    sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    
    pthread_mutex_unlock(&session->db_mutex);
}

/* Recherche des messages (commande /search) */
void db_search_messages(ChatSession *session, const char *search_term) {
    pthread_mutex_lock(&session->db_mutex);
    
    if (!session->history_db) {
        printf(COLOR_RED "[!] Base de données non disponible.\n" COLOR_RESET);
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = "SELECT timestamp, sender, recipient, type, content "
                      "FROM messages "
                      "WHERE content LIKE ? OR sender LIKE ? "
                      "ORDER BY timestamp DESC "
                      "LIMIT 50;";
    
    if (sqlite3_prepare_v2(session->history_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf(COLOR_RED "[!] Erreur lors de la recherche\n" COLOR_RESET);
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    char like_term[256];
    snprintf(like_term, sizeof(like_term), "%%%s%%", search_term);
    sqlite3_bind_text(stmt, 1, like_term, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, like_term, -1, SQLITE_STATIC);
    
    printf(COLOR_CYAN "\n🔍 Recherche : \"%s\"\n" COLOR_RESET, search_term);
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    
    int result_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        result_count++;
        const char *timestamp = (const char*)sqlite3_column_text(stmt, 0);
        const char *sender = (const char*)sqlite3_column_text(stmt, 1);
        const char *recipient = (const char*)sqlite3_column_text(stmt, 2);
        const char *type = (const char*)sqlite3_column_text(stmt, 3);
        const char *content = (const char*)sqlite3_column_text(stmt, 4);

        if (strcmp(type, "SYSTEM") == 0) {
            printf("[%s]",timestamp);
            printf(COLOR_YELLOW "[SYSTÈME]" COLOR_RESET);
            if (strcmp(content, "HEARTBEAT") == 0){
                printf("%s est en ligne.\n",sender);
            }
            if (strcmp(content, "GOODBYE") == 0){
                printf("%s s'est deconnecté(e).\n",sender);
            } else {
                printf("%s:%s\n",sender, content);
            }
        }
        if (strcmp(type, "PRIVATE") == 0) {
            if (strcmp(recipient, "ALL") == 0) {
                printf("[%s] ", timestamp);
                printf(COLOR_MAGENTA "[PRIVÉ À TOUS] " COLOR_RESET);
                printf("%s: %s\n", sender, content);
            } else {
                printf("[%s] ", timestamp);
                printf(COLOR_MAGENTA "[PRIVÉ] " COLOR_RESET);
                printf("%s → %s: %s\n", sender, recipient, content);
            }
        } else {
            printf("[%s] %s: %s\n", timestamp, sender, content);
        }
    }
    
    if (result_count == 0) {
        printf(COLOR_YELLOW "Aucun résultat trouvé.\n" COLOR_RESET);
    } else {
        printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
        printf(COLOR_GREEN "✓ %d résultat(s) trouvé(s)\n" COLOR_RESET, result_count);
    }
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&session->db_mutex);
}

/* Affiche les derniers messages (commande /history) */
void db_show_last_messages(ChatSession *session, int count) {
    pthread_mutex_lock(&session->db_mutex);
    
    if (!session->history_db) {
        printf(COLOR_RED "[!] Base de données non disponible\n" COLOR_RESET);
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    sqlite3_stmt *stmt;
    const char *sql = "SELECT timestamp, sender, recipient, type, content "
                      "FROM messages WHERE type!='SYSTEM'"
                      "ORDER BY timestamp DESC "
                      "LIMIT ?;";
    
    if (sqlite3_prepare_v2(session->history_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        printf(COLOR_RED "[!] Erreur lors de la lecture\n" COLOR_RESET);
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    sqlite3_bind_int(stmt, 1, count);
    
    printf(COLOR_CYAN "\n📜 Derniers %d messages\n" COLOR_RESET, count);
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    
    int message_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        message_count++;
        const char *timestamp = (const char*)sqlite3_column_text(stmt, 0);
        const char *sender = (const char*)sqlite3_column_text(stmt, 1);
        const char *recipient = (const char*)sqlite3_column_text(stmt, 2);
        const char *type = (const char*)sqlite3_column_text(stmt, 3);
        const char *content = (const char*)sqlite3_column_text(stmt, 4);
        
        if (strcmp(type, "SYSTEM") == 0) {
            printf("[%s]",timestamp);
            printf(COLOR_YELLOW "[SYSTÈME]" COLOR_RESET);
            if (strcmp(content, "HEARTBEAT") == 0){
                printf("%s est en ligne.\n",sender);
            }
            if (strcmp(content, "GOODBYE") == 0){
                printf("%s s'est deconnevté(e).\n",sender);
            } else {
                printf("%s:%s\n",sender, content);
            }
        }
        else if (strcmp(type, "PRIVATE") == 0) {
            if (strcmp(recipient, "ALL") == 0) {
                printf("[%s] ", timestamp);
                printf(COLOR_MAGENTA "[PRIVÉ À TOUS] " COLOR_RESET);
                printf("%s: %s\n", sender, content);
            } else {
                printf("[%s] ", timestamp);
                printf(COLOR_MAGENTA "[PRIVÉ] " COLOR_RESET);
                printf("%s → %s: %s\n", sender, recipient, content);
            }
        } else {
            printf("[%s] %s: %s\n", timestamp, sender, content);
        }
    }
    
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_GREEN "✓ %d message(s) affiché(s)\n" COLOR_RESET, message_count);
    
    sqlite3_finalize(stmt);
    pthread_mutex_unlock(&session->db_mutex);
}

/* Affiche les statistiques (commande /stats) */
void db_show_stats(ChatSession *session) {
    pthread_mutex_lock(&session->db_mutex);
    
    if (!session->history_db) {
        printf(COLOR_RED "[!] Base de données non disponible.\n" COLOR_RESET);
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    printf(COLOR_CYAN "\n📊 Statistiques de votre historique\n" COLOR_RESET);
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    
    /* Nombre total de messages */
    sqlite3_stmt *stmt;
    const char *sql_total = "SELECT COUNT(*) FROM messages WHERE type!='SYSTEM';";
    if (sqlite3_prepare_v2(session->history_db, sql_total, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int total = sqlite3_column_int(stmt, 0);
            printf("📨 Messages totaux: %d\n", total);
        }
        sqlite3_finalize(stmt);
    }
    
    /* Messages envoyés par vous */
    char sql_sent[256];
    snprintf(sql_sent, sizeof(sql_sent), 
             "SELECT COUNT(*) FROM messages WHERE sender='%s';", session->username);
    if (sqlite3_prepare_v2(session->history_db, sql_sent, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int sent = sqlite3_column_int(stmt, 0);
            printf("📤 Message(s) envoyé(s): %d\n", sent);
        }
        sqlite3_finalize(stmt);
    }
    
    /* Messages privés */
    const char *sql_private = "SELECT COUNT(*) FROM messages WHERE type='PRIVATE';";
    if (sqlite3_prepare_v2(session->history_db, sql_private, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int private = sqlite3_column_int(stmt, 0);
            printf("🔒 Message(s) privé(s): %d\n", private);
        }
        sqlite3_finalize(stmt);
    }
        /* Messages système */
    const char *sql_system = "SELECT COUNT(*) FROM messages WHERE type='SYSTEM';";
    if (sqlite3_prepare_v2(session->history_db, sql_system, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int system = sqlite3_column_int(stmt, 0);
            printf("🔒 Évènement(s) système(s): %d\n", system);
        }
        sqlite3_finalize(stmt);
    }
    /* Premier et dernier message */
    const char *sql_range = "SELECT MIN(timestamp), MAX(timestamp) FROM messages;";
    if (sqlite3_prepare_v2(session->history_db, sql_range, -1, &stmt, NULL) == SQLITE_OK) {
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *first = (const char*)sqlite3_column_text(stmt, 0);
            const char *last = (const char*)sqlite3_column_text(stmt, 1);
            if (first && last) {
                printf("📅 Période: %s → %s\n", first, last);
            }
        }
        sqlite3_finalize(stmt);
    }
    
    /* Top 3 des correspondants */
    printf(COLOR_CYAN "\n👥 Top 3 des correspondants:\n" COLOR_RESET);
    const char *sql_top = "SELECT sender, COUNT(*) as count "
                          "FROM messages WHERE sender != ? "
                          "GROUP BY sender ORDER BY count DESC LIMIT 3;";
    if (sqlite3_prepare_v2(session->history_db, sql_top, -1, &stmt, NULL) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, session->username, -1, SQLITE_STATIC);
        int rank = 1;
        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const char *sender = (const char*)sqlite3_column_text(stmt, 0);
            int count = sqlite3_column_int(stmt, 1);
            printf("  %d. %s: %d messages\n", rank++, sender, count);
        }
        sqlite3_finalize(stmt);
    }
    
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    
    pthread_mutex_unlock(&session->db_mutex);
}

/* Exporte l'historique en CSV (commande /export) */
void db_export_to_csv(ChatSession *session) {
    pthread_mutex_lock(&session->db_mutex);
    
    if (!session->history_db) {
        printf(COLOR_RED "[!] Base de données non disponible.\n" COLOR_RESET);
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    char filename[256];
    snprintf(filename, sizeof(filename), "chat_export_%s.csv", session->username);
    
    FILE *csv_file = fopen(filename, "w");
    if (!csv_file) {
        printf(COLOR_RED "[!] Impossible de créer le fichier %s\n" COLOR_RESET, filename);
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    /* En-tête CSV */
    fprintf(csv_file, "ID;Timestamp;Expéditeur;Destinataire;Type;Contenu\n");
    
    /* Récupération des données */
    sqlite3_stmt *stmt;
    const char *sql = "SELECT id, timestamp, sender, recipient, type, content "
                      "FROM messages WHERE type!='SYSTEM' ORDER BY timestamp;";
    
    if (sqlite3_prepare_v2(session->history_db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        fclose(csv_file);
        pthread_mutex_unlock(&session->db_mutex);
        return;
    }
    
    int exported = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        const char *timestamp = (const char*)sqlite3_column_text(stmt, 1);
        const char *sender = (const char*)sqlite3_column_text(stmt, 2);
        const char *recipient = (const char*)sqlite3_column_text(stmt, 3);
        const char *type = (const char*)sqlite3_column_text(stmt, 4);
        const char *content = (const char*)sqlite3_column_text(stmt, 5);
        
        fprintf(csv_file, "%d;%s;%s;%s;%s;%s\n", 
                id, timestamp, sender, recipient, type, content);
        exported++;
    }
    
    sqlite3_finalize(stmt);
    fclose(csv_file);
    
    printf(COLOR_GREEN "[✓] Export réussi : %d messages dans %s" COLOR_RESET, 
           exported, filename);
    printf(".\n");
    printf(COLOR_YELLOW "[i] Ouvrez-le avec Excel ou LibreOffice Calc.\n" COLOR_RESET);
    
    pthread_mutex_unlock(&session->db_mutex);
}

/* ==================== FONCTIONS D'AFFICHAGE ==================== */

void enableANSI() {
#ifdef _WIN32
    HANDLE hout = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    GetConsoleMode(hout, &dwMode);
    dwMode |= 0x0004;
    SetConsoleMode(hout, dwMode);
#endif
}

void print_colored_banner(const char *text, char border_char, const char* color, int large) {
    int width = large ? 80 : 50;
    int height = large ? 7 : 3;
    int text_len = strlen(text);
    int padding = (width - 2 - text_len) / 2;
    int i, j;
    
    printf("\n");
    printf("%s", color);
    
    for (i = 0; i < width; i++) printf("%c", border_char);
    printf("\n");
    
    for (i = 0; i < height / 2 - 1; i++) {
        printf("%c", border_char);
        for (j = 0; j < width - 2; j++) printf(" ");
        printf("%c\n", border_char);
    }
    
    printf("%c", border_char);
    for (i = 0; i < padding; i++) printf(" ");
    printf(COLOR_BOLD COLOR_YELLOW "%s" COLOR_RESET "%s", text, color);
    for (i = 0; i < width - 2 - padding - text_len; i++) printf(" ");
    printf("%c\n", border_char);
    
    for (i = 0; i < height / 2 - 1; i++) {
        printf("%c", border_char);
        for (j = 0; j < width - 2; j++) printf(" ");
        printf("%c\n", border_char);
    }
    
    for (i = 0; i < width; i++) printf("%c", border_char);
    printf(COLOR_RESET "\n\n");
}

void print_main_banner(void) {
    print_colored_banner(" APPLICATION DE MESSAGERIE INSTANTANÉE (AMI)", '*', COLOR_CYAN, 1);
}

void display_user_welcome(const char* username) {
    printf("\n");
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n");
    printf(COLOR_YELLOW "          Now, you have the floor...             \n");
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
}

void display_goodbye_message(const char* username) {
    printf("\n");
    print_colored_banner("AU REVOIR & A BIENTOT", '=', COLOR_YELLOW, 0);
    
    printf(COLOR_YELLOW "|" COLOR_RESET "  Merci d'avoir utilisé AMI, ");
    print_colored_username(username);
    printf(COLOR_RESET " !\n");
    printf(COLOR_YELLOW "|" COLOR_RESET "  Historique sauvegardé dans : chat_%s.\n", username);
    printf(COLOR_YELLOW "+");
    for (int i = 0; i < 48; i++) printf("-");
    printf("+\n" COLOR_RESET);
    printf("\n");
    #ifdef _WIN32
            Sleep(500);
    #else
            usleep(500000);
    #endif
}

void display_help(void) {
    printf("\n");
    printf(COLOR_CYAN "╔══════════════════════════════════════════════╗\n" COLOR_RESET);
    printf(COLOR_CYAN "║            COMMANDES DISPONIBLES             ║\n" COLOR_RESET);
    printf(COLOR_CYAN "╠══════════════════════════════════════════════╣\n" COLOR_RESET);
    printf(COLOR_CYAN "║                                              ║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_GREEN "CHAT & RÉSEAU" COLOR_CYAN "                               ║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/aide" COLOR_RESET "        - Afficher cette aide          " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/liste" COLOR_RESET "       - Lister les utilisateurs      " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "@user msg" COLOR_RESET "    - Message privé                " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/silence" COLOR_RESET "     - Mode silencieux ON/OFF       " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/effacer" COLOR_RESET "     - Effacer l'écran              " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║                                              ║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_GREEN "HISTORIQUE SQLite" COLOR_CYAN "                           ║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/search mot" COLOR_RESET "  - Rechercher dans l'historique " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/history N" COLOR_RESET "   - Afficher N derniers messages " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/stats" COLOR_RESET "       - Afficher vos statistiques    " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/export" COLOR_RESET "      - Exporter en CSV (Excel)      " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║                                              ║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_GREEN "SYSTÈME" COLOR_CYAN "                                     ║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/infos" COLOR_RESET "       - Informations système         " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║  " COLOR_MAGENTA "/quitter" COLOR_RESET "     - Quitter le chat              " COLOR_CYAN "║\n" COLOR_RESET);
    printf(COLOR_CYAN "║                                              ║\n" COLOR_RESET);
    printf(COLOR_CYAN "╚══════════════════════════════════════════════╝\n" COLOR_RESET);
    printf("\n");
}

void print_colored_username(const char* username) {
    unsigned int hash = 0;
    int i;
    
    for (i = 0; username[i] != '\0'; i++) {
        hash = username[i] + (hash << 6) + (hash << 16) - hash;
    }
    
    int color_idx = hash % 8;
    switch (color_idx) {
        case 0: printf(COLOR_RED "%s" COLOR_RESET, username); break;
        case 1: printf(COLOR_GREEN "%s" COLOR_RESET, username); break;
        case 2: printf(COLOR_YELLOW "%s" COLOR_RESET, username); break;
        case 3: printf(COLOR_BLUE "%s" COLOR_RESET, username); break;
        case 4: printf(COLOR_MAGENTA "%s" COLOR_RESET, username); break;
        case 5: printf(COLOR_CYAN "%s" COLOR_RESET, username); break;
        case 6: printf(COLOR_ORANGE "%s" COLOR_RESET, username); break;
        case 7: printf(COLOR_PINK "%s" COLOR_RESET, username); break;
        default: printf("%s", username); break;
    }
}

void print_message_received(const char* timestamp, const char* username,
                          const char* message) {
    if (prompt_displayed){
            printf("\r\033[K");
    }

    printf(COLOR_CYAN "==> [%s] " COLOR_RESET, timestamp);
    print_colored_username(username);
    printf(" : %s\n", message);
}


void print_notification(const char* type, const char* message) {
    
    if (prompt_displayed){
        printf("\r\033[K");
    }
    
    if (strcmp(type, "join") == 0) {
        printf(COLOR_GREEN "[+] %s a rejoint le chat :)\n" COLOR_RESET, message);
    } else if (strcmp(type, "leave") == 0) {
        printf(COLOR_ORANGE "[-] %s s'est déconnecté(e) :(\n" COLOR_RESET, message);
    } else if (strcmp(type, "timeout") == 0) {
        printf(COLOR_RED "[i] %s inactif trop longtemps...\n" COLOR_RESET, message);
    } else if (strcmp(type, "system") == 0) {
        printf(COLOR_BLUE "[i] %s\n" COLOR_RESET, message);
    }
}

void print_private_received(const char* timestamp, const char* from_user,
                          const char* message) {

    if (prompt_displayed){
        printf("\r\033[K");
    }
    printf(COLOR_MAGENTA "--> [%s] Message privé de " COLOR_RESET, timestamp);
    print_colored_username(from_user);
    printf(": %s\n", message);

}

void get_timestamp(char* buffer, size_t size) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}
void display_input_prompt(ChatSession* session) {
    printf("\r\033[K");
    printf("\n[Votre message] ");
    print_colored_username(session->username);
    printf(COLOR_CYAN" > "COLOR_RESET);
    fflush(stdout);
    prompt_displayed = 1;
}

/* AJOUT : Fonction de vérification du timeout des utilisateurs */
void check_user_timeouts(ChatSession* session) {
    time_t now = time(NULL);
    int i;
    
    for (i = 0; i < session->user_count; i++) {
        /* Ignorer notre propre utilisateur */
        if (strcmp(session->users[i].username, session->username) == 0) {
            continue;
        }
        
        /* Vérifier si l'utilisateur est marqué comme en ligne mais inactif */
        if (session->users[i].is_online && 
            (now - session->users[i].last_seen) > USER_TIMEOUT) {
            
            session->users[i].is_online = 0;
            
            if (!session->silent_mode) {
                print_notification("timeout", session->users[i].username);
                
                /* Sauvegarder l'événement dans la base */
                char timestamp[20];
                get_timestamp(timestamp, sizeof(timestamp));
                save_message_to_db(session, timestamp, 
                                  session->users[i].username,
                                  "SYSTEM", "SYSTEM", "TIMEOUT");
                
                /* Réafficher le prompt */
                display_input_prompt(session);
                if (input_pos > 0){
                    printf("%.*s", input_pos, input_buffer);
                    fflush(stdout);
                }
            }
        }
    }
}


void save_input_line(void){
    printf("\033[s");
}

void restore_input_line(void){
    printf("\033[u");
}

/* ==================== FONCTIONS RÉSEAU ==================== */

void init_network(void) {
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, COLOR_RED "Erreur WSAStartup\n" COLOR_RESET);
        exit(1);
    }
#endif
}

void cleanup_network(void) {
#ifdef _WIN32
    WSACleanup();
#endif
}

void get_local_ip(char* buffer, size_t size) {
    strcpy(buffer, "127.0.0.1");
    
#ifdef _WIN32
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        struct hostent* host = gethostbyname(hostname);
        if (host && host->h_addr_list[0]) {
            struct in_addr addr;
            memcpy(&addr, host->h_addr_list[0], sizeof(struct in_addr));
            strncpy(buffer, inet_ntoa(addr), size - 1);
        }
    }
#else
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == 0) {
        for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL) continue;
            if (ifa->ifa_addr->sa_family == AF_INET) {
                struct sockaddr_in* sa = (struct sockaddr_in*)ifa->ifa_addr;
                char* ip = inet_ntoa(sa->sin_addr);
                
                if (strcmp(ip, "127.0.0.1") != 0 && 
                    (ifa->ifa_flags & IFF_UP) && 
                    !(ifa->ifa_flags & IFF_LOOPBACK)) {
                    strncpy(buffer, ip, size - 1);
                    break;
                }
            }
        }
        freeifaddrs(ifaddr);
    }
#endif
    buffer[size - 1] = '\0';
}

SOCKET create_multicast_socket(const char* multicast_ip, int port, int ttl) {
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == INVALID_SOCKET) {
        perror("Erreur création socket");
        return INVALID_SOCKET;
    }
    
    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, 
                  (char*)&reuse, sizeof(reuse)) < 0) {
        perror("Erreur setsockopt SO_REUSEADDR");
        close(sock);
        return INVALID_SOCKET;
    }
    
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, 
                  (char*)&ttl, sizeof(ttl)) < 0) {
        perror("Erreur setsockopt IP_MULTICAST_TTL");
        close(sock);
        return INVALID_SOCKET;
    }
    
    /* IMPORTANT : Activer la boucle multicast */
    int loop = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_MULTICAST_LOOP, 
                  (char*)&loop, sizeof(loop)) < 0) {
        perror("Erreur setsockopt IP_MULTICAST_LOOP");
    }
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Erreur bind");
        close(sock);
        return INVALID_SOCKET;
    }
    
    return sock;
}

int join_multicast_group(SOCKET sock, const char* multicast_ip) {
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
   
    // Première tentative
    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                  (char*)&mreq, sizeof(mreq)) < 0) {
        
        #ifdef _WIN32
            int error = WSAGetLastError();
            if (error == WSAEADDRINUSE || error == 10048) {
                // Le groupe est déjà utilisé, essayer de quitter d'abord
                printf(COLOR_YELLOW "[!] Groupe multicast occupé, tentative de nettoyage...\n" COLOR_RESET);
                
                // Essayer de quitter (au cas où)
                setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP,
                          (char*)&mreq, sizeof(mreq));
                
                Sleep(500);  // Attendre que le système libère
                
                // Réessayer
                if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP,
                              (char*)&mreq, sizeof(mreq)) < 0) {
                    fprintf(stderr, COLOR_RED "Erreur IP_ADD_MEMBERSHIP (code %d)\n" COLOR_RESET, WSAGetLastError());
                    return 0;
                }
                
                printf(COLOR_GREEN "[✓] Groupe multicast rejoint après nettoyage\n" COLOR_RESET);
                return 1;
            }
        #endif
        
        perror("Erreur setsockopt IP_ADD_MEMBERSHIP");
        return 0;
    }
    
    return 1;
}



int leave_multicast_group(SOCKET sock, const char* multicast_ip) {
    struct ip_mreq mreq;
    mreq.imr_multiaddr.s_addr = inet_addr(multicast_ip);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    
    if (setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, 
                  (char*)&mreq, sizeof(mreq)) < 0) {
        perror("Erreur setsockopt IP_DROP_MEMBERSHIP");
        return 0;
    }
    return 1;
}


/* ==================== FONCTIONS DE GESTION UTILISATEURS ==================== */

void list_users(ChatSession* session) {
    int i;
    int online_count = 0;
    time_t now = time(NULL);
    
    printf("\n");
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    printf(COLOR_CYAN "            UTILISATEURS CONNECTÉS               \n" COLOR_RESET);
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    
    for (i = 0; i < session->user_count; i++) {
        if (session->users[i].is_online) {
            if ((now - session->users[i].last_seen) > USER_TIMEOUT){
                session->users[i].is_online = 0;
                continue;
            }

            online_count++;
            char timestamp[20];
            struct tm* tm_info = localtime(&session->users[i].last_seen);
            strftime(timestamp, sizeof(timestamp), "%H:%M:%S", tm_info);
            if (online_count != 0) {
                printf("  • ");
                print_colored_username(session->users[i].username);
                printf(" - Actif à %s (%s)\n", timestamp, session->users[i].ip);
            }
        }
    }
    
    if (online_count != 0) {
        printf(COLOR_BLUE "\n  %d utilisateur(s) connecté(s).\n" COLOR_RESET, count_online_users(session));
    }
    if (online_count == 0) {
        printf("  Aucun autre utilisateur connecté\n");
    }
    
    printf(COLOR_CYAN "═══════════════════════════════════════════════════\n" COLOR_RESET);
    printf("\n");
}
/* AJOUT : Fonction de recherche d'utilisateur */
UserInfo* find_user(ChatSession* session, const char* username) {
    int i;
    time_t now = time(NULL);
    
    for (i = 0; i < session->user_count; i++) {
        if (strcmp(session->users[i].username, username) == 0) {
            /* Vérifier si l'utilisateur n'est pas en timeout */
            if ((now - session->users[i].last_seen) > USER_TIMEOUT) {
                session->users[i].is_online = 0;
            }
            return &session->users[i];
        }
    }
    return NULL;
}

/* AJOUT : Vérification si un utilisateur est en ligne */
int is_user_online(ChatSession* session, const char* username) {
    UserInfo* user = find_user(session, username);
    
    if (user == NULL) {
        return 0;  /* Utilisateur introuvable */
    }
    
    return user->is_online;
}

int send_private_message(ChatSession* session, const char* target_user, 
                         const char* message) {

    if (strcmp(target_user, session->username) == 0) {
        printf(COLOR_RED "[!] Vous ne pouvez pas vous envoyer un message privé.\n" COLOR_RESET);
        return 0;
    }

    if (!is_user_online(session, target_user)) {
        printf(COLOR_RED "[!] Utilisateur introuvable ou déconnecté.\n" COLOR_RESET);
        printf(COLOR_ORANGE "[i] Tapez /liste pour voir les utilisateurs connectés.\n" COLOR_RESET);
        return 0;
    }

    char buffer[MAX_BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "PRIVATE|%s|%s|%s", 
            session->username, target_user, message);
    
    sendto(session->sock, buffer, strlen(buffer), 0,
          (struct sockaddr*)&session->multicast_addr,
          sizeof(session->multicast_addr));
    
    //Afficher confirmation locale
    printf(COLOR_MAGENTA "[→] Message privé envoyé avec succès à " COLOR_RESET);
    print_colored_username(target_user);
    printf(".\n");
    return 1;
}

/* AJOUT : Fonction pour compter les utilisateurs en ligne */
int count_online_users(ChatSession* session) {
    int count = 0;
    int i;
    time_t now = time(NULL);
    
    for (i = 0; i < session->user_count; i++) {
        /* Ignorer notre propre utilisateur */
        if (strcmp(session->users[i].username, session->username) == 0) {
            continue;
        }
        
        /* Vérifier le timeout */
        if (session->users[i].is_online && 
            (now - session->users[i].last_seen) <= USER_TIMEOUT) {
            count++;
        }
    }
    
    return count;
}

void send_heartbeat(ChatSession* session) {
    char buffer[MAX_BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "HEARTBEAT|%s", session->username);
    
    sendto(session->sock, buffer, strlen(buffer), 0,
          (struct sockaddr*)&session->multicast_addr,
          sizeof(session->multicast_addr));
}

void send_goodbye(ChatSession* session) {
    char buffer[MAX_BUFFER_SIZE];
    snprintf(buffer, sizeof(buffer), "GOODBYE|%s", session->username);
    
    sendto(session->sock, buffer, strlen(buffer), 0,
          (struct sockaddr*)&session->multicast_addr,
          sizeof(session->multicast_addr));
}


void update_user_list(ChatSession* session, const char* username,
                     const char* ip, int is_heartbeat) {
    int i;
    int is_new_user = 1;
    int was_offline = 0;
    
    /* Ne pas traiter notre propre utilisateur dans les notifications */
    int is_self = (strcmp(username, session->username) == 0);
    
    /* Chercher l'utilisateur dans la liste */
    for (i = 0; i < session->user_count; i++) {
        if (strcmp(session->users[i].username, username) == 0) {
            is_new_user = 0;
            was_offline = !session->users[i].is_online;
            
            /* Mettre à jour les informations */
            session->users[i].last_seen = time(NULL);
            strncpy(session->users[i].ip, ip, 15);
            session->users[i].ip[15] = '\0';
            session->users[i].is_online = 1;
            
            /* Notifier si l'utilisateur revient après être parti */
            if (was_offline && !is_heartbeat && !is_self && !session->silent_mode) {
                print_notification("join", username);
                display_input_prompt(session);
                if (input_pos > 0){
                    printf("%.*s", input_pos, input_buffer);
                    fflush(stdout);
                }

            }
            
            return;
        }
    }
    
    /* Nouvel utilisateur */
    if (is_new_user && session->user_count < MAX_USERS) {
        UserInfo* user = &session->users[session->user_count];
        strncpy(user->username, username, MAX_USERNAME - 1);
        user->username[MAX_USERNAME - 1] = '\0';
        strncpy(user->ip, ip, 15);
        user->ip[15] = '\0';
        user->last_seen = time(NULL);
        user->is_online = 1;
        session->user_count++;
        
        /* Notification de nouveau membre (sauf pour nous-mêmes et en mode heartbeat) */
        if (!is_heartbeat && !is_self && !session->silent_mode) {
            print_notification("join", username);
            display_input_prompt(session);
            if (input_pos > 0){
                printf("%.*s", input_pos, input_buffer);
                fflush(stdout);
            }
        }
    }
}


/* ==================== FONCTIONS D'ENTRÉE/SORTIE ==================== */

int kbhit(void) {
#ifdef _WIN32
    return _kbhit();
#else
    struct termios oldt, newt;
    int ch;
    int oldf;
    
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    oldf = fcntl(STDIN_FILENO, F_GETFL, 0);
    fcntl(STDIN_FILENO, F_SETFL, oldf | O_NONBLOCK);
    
    ch = getchar();
    
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    fcntl(STDIN_FILENO, F_SETFL, oldf);
    
    if (ch != EOF) {
        ungetc(ch, stdin);
        return 1;
    }
    return 0;
#endif
}

/* ==================== NETTOYAGE ==================== */

void cleanup_and_exit(ChatSession* session) {
    if (session && session->running) {
        printf(COLOR_ORANGE "\n[!] Déconnexion en cours...\n" COLOR_RESET);
        send_goodbye(session);
        
#ifdef _WIN32
        Sleep(200);
#else
        usleep(200000);
#endif
        
        display_goodbye_message(session->username);
        
        if (session->sock != INVALID_SOCKET) {
            leave_multicast_group(session->sock, MULTICAST_GROUP);
            close(session->sock);
        }
        
        close_sqlite_database(session);
        pthread_mutex_destroy(&session->db_mutex);
        
        cleanup_network();
        session->running = 0;
    }
}

/* ==================== FONCTION PRINCIPALE ==================== */

int main(int argc, char* argv[]) {
    //configuration de l'encodage
    #ifdef _WIN32
        SetConsoleOutputCP(CP_UTF8);
        SetConsoleCP(CP_UTF8);
    #else  
        setlocale(LC_ALL,"fr_FR.UTF-8");
    #endif

    #ifdef _WIN32
        if (GetConsoleOutputCP() != CP_UTF8){
            fprintf(stderr,"Attention: Console n'est pas en UTF-8\n");
        }
    #endif

    ChatSession session;
    //char input_buffer[MAX_MESSAGE];
    input_pos = 0;
    memset(input_buffer, 0, sizeof(input_buffer));
    char message_buffer[MAX_BUFFER_SIZE];
    char timestamp[20];
    time_t last_heartbeat = 0;
    int i;
    
    enableANSI();
    memset(&session, 0, sizeof(session));
    strcpy(session.channel, "general");
    session.running = 1;
    session.silent_mode = 0;
    
    global_session_ptr = &session;
    
#ifdef _WIN32
    SetConsoleCtrlHandler(console_handler, TRUE);
#else
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
#endif
    
    system(CLEAR_SCREEN);
    print_main_banner();
    
    init_network();
    
    printf(COLOR_BOLD COLOR_CYAN "Entrez votre pseudo" COLOR_RESET " (max %d caractères): ", 
           MAX_USERNAME - 1);
    fflush(stdout);
    
    if (fgets(session.username, sizeof(session.username), stdin) == NULL) {
        fprintf(stderr, COLOR_RED "Erreur de lecture du pseudo\n" COLOR_RESET);
        cleanup_network();
        return 1;
    }
    
    session.username[strcspn(session.username, "\n")] = '\0';
    
    if (strlen(session.username) == 0) {
        strcpy(session.username, "Anonyme");
    }
    
    display_user_welcome(session.username);
    
    pthread_mutex_init(&session.db_mutex, NULL);
    
    if (!init_sqlite_database(&session)) {
        printf(COLOR_YELLOW "[!] Historique SQLite désactivé.\n" COLOR_RESET);
    }
    
    session.sock = create_multicast_socket(MULTICAST_GROUP, MULTICAST_PORT, 2);
    if (session.sock == INVALID_SOCKET) {
        cleanup_network();
        return 1;
    }
    
    if (!join_multicast_group(session.sock, MULTICAST_GROUP)) {
        close(session.sock);
        cleanup_network();
        return 1;
    }
    
    memset(&session.multicast_addr, 0, sizeof(session.multicast_addr));
    session.multicast_addr.sin_family = AF_INET;
    session.multicast_addr.sin_addr.s_addr = inet_addr(MULTICAST_GROUP);
    session.multicast_addr.sin_port = htons(MULTICAST_PORT);
    
    update_user_list(&session, session.username, "127.0.0.1", 0);
    
    send_heartbeat(&session);
    
    printf(COLOR_GREEN "\n[✓] Prêt à chatter! Tapez /aide pour les commandes.\n\n" COLOR_RESET);
    
    display_input_prompt(&session);
    
    while (session.running) {
#ifndef _WIN32
        if (exit_flag) {
            printf(COLOR_YELLOW "\n\n[!] Ctrl+C détecté. Déconnexion...\n" COLOR_RESET);
            session.running = 0;
            continue;
        }
#endif
        
        fd_set readfds;
        struct timeval tv;
        
        FD_ZERO(&readfds);
        FD_SET(session.sock, &readfds);
        
        tv.tv_sec = 0;
        tv.tv_usec = 50000;
        
        if (select(session.sock + 1, &readfds, NULL, NULL, &tv) > 0) {
            if (FD_ISSET(session.sock, &readfds)) {
                struct sockaddr_in src_addr;
                socklen_t addr_len = sizeof(src_addr);
                char buffer[MAX_BUFFER_SIZE];
                int bytes_received;
                char* src_ip;
                char* token;
                char* username;
                char* message;
                char* target_user;
                char* from_user;
                char* to_user;
                
                bytes_received = recvfrom(session.sock, buffer, 
                                         sizeof(buffer) - 1, 0,
                                         (struct sockaddr*)&src_addr, 
                                         &addr_len);
                
                if (bytes_received > 0) {
                    buffer[bytes_received] = '\0';
                    src_ip = inet_ntoa(src_addr.sin_addr);
                    
                    token = strtok(buffer, "|");
                    if (token) {
                        if (strcmp(token, "HEARTBEAT") == 0) {
                            username = strtok(NULL, "|");
                            if (username && strcmp(username, session.username) != 0) {
                                update_user_list(&session, username, src_ip, 0);
                            }
                        }
                        else if (strcmp(token, "MESSAGE") == 0) {
                            username = strtok(NULL, "|");
                            message = strtok(NULL, "");
                            
                            if (username && message && strcmp(username, session.username) != 0) {
                                get_timestamp(timestamp, sizeof(timestamp));
                                if (strcmp(username, session.username) != 0){
                                    printf("Ok");
                                    print_message_received(timestamp, username, message);
                                }
                                save_message_to_db(&session, timestamp, username, 
                                                  "ALL", "PUBLIC", message);
                                update_user_list(&session, username, src_ip, 0);
                                
                                display_input_prompt(&session);
                                if (input_pos > 0){
                                    printf("%.*s", input_pos, input_buffer);
                                    fflush(stdout);
                                }
                            }
                        }
                        else if (strcmp(token, "PRIVATE") == 0) {
                            from_user = strtok(NULL, "|");
                            to_user = strtok(NULL, "|");
                            message = strtok(NULL, "");
                            
                            if (from_user && to_user && message &&
                                strcmp(to_user, session.username) == 0) {
                                
                                get_timestamp(timestamp, sizeof(timestamp));
                                print_private_received(timestamp, from_user, message);
                                
                                save_message_to_db(&session, timestamp, from_user, 
                                                  session.username, "PRIVATE", message);//ici vous en session.username
                                
                                display_input_prompt(&session);
                                if (input_pos > 0){
                                    printf("%.*s", input_pos, input_buffer);
                                    fflush(stdout);
                                }
                            }
                        }
                        else if (strcmp(token, "GOODBYE") == 0) {
                            username = strtok(NULL, "|");
                            if (username && !session.silent_mode && strcmp(username, session.username) != 0) {
                                print_notification("leave", username);
                                for (i = 0; i < session.user_count; i++) {
                                    if (strcmp(session.users[i].username, username) == 0) {
                                        session.users[i].is_online = 0;
                                        break;
                                    }
                                }
                                get_timestamp(timestamp, sizeof(timestamp));
                                save_message_to_db(&session, timestamp, username, 
                                                  "SYSTEM", "SYSTEM", "GOODBYE");
                                display_input_prompt(&session);
                                if (input_pos > 0){
                                    printf("%.*s", input_pos, input_buffer);
                                    fflush(stdout);
                                }
                            }
                        }
                    }
                }
            }
        }
        
        if (kbhit()) {
#ifdef _WIN32
    int ch = _getch();
#else
    int ch = getchar();
#endif
    
    if (ch == '\n' || ch == '\r') {  // Entrée pressée
        input_buffer[input_pos] = '\0';
        printf("\n");
        
        if (input_pos > 0) {
            // TRAITEMENT DES COMMANDES
            if (input_buffer[0] == '/') {
                if (strcmp(input_buffer, "/quitter") == 0 || strcmp(input_buffer, "/exit") == 0) {
                    send_goodbye(&session);
#ifdef _WIN32
                    Sleep(100);
#else
                    usleep(100000);
#endif
                    display_goodbye_message(session.username);
                    session.running = 0;
                    break;
                }
                else if (strcmp(input_buffer, "/aide") == 0) {
                    display_help();
                    display_input_prompt(&session);
                }
                else if (strcmp(input_buffer, "/infos") == 0) {
                    printf(COLOR_CYAN "\n[i] Chat P2P - Multicast UDP\n" COLOR_RESET);
                    printf(COLOR_CYAN "[i] Groupe: %s:%d\n" COLOR_RESET, MULTICAST_GROUP, MULTICAST_PORT);
                    printf(COLOR_CYAN "[i] Base SQLite: chat_%s.db\n" COLOR_RESET, session.username);
                    display_input_prompt(&session);
                }
                else if (strcmp(input_buffer, "/liste") == 0) {
                    list_users(&session);
                    display_input_prompt(&session);
                }
                else if (strncmp(input_buffer, "/search ", 8) == 0) {
                    char *search_term = input_buffer + 8;
                    if (strlen(search_term) > 0) {
                        db_search_messages(&session, search_term);
                    } else {
                        printf(COLOR_RED "Usage: /search <mot>\n" COLOR_RESET);
                    }
                    display_input_prompt(&session);
                }
                else if (strncmp(input_buffer, "/history ", 9) == 0) {
                    int count = atoi(input_buffer + 9);
                    if (count <= 0) count = 20;
                    if (count > 100) count = 100;
                    db_show_last_messages(&session, count);
                    display_input_prompt(&session);
                }
                else if (strcmp(input_buffer, "/history") == 0) {
                    db_show_last_messages(&session, 20);
                    display_input_prompt(&session);
                }
                else if (strcmp(input_buffer, "/stats") == 0) {
                    db_show_stats(&session);
                    display_input_prompt(&session);
                }
                else if (strcmp(input_buffer, "/export") == 0) {
                    db_export_to_csv(&session);
                    display_input_prompt(&session);
                }
                else if (strncmp(input_buffer, "/prive", 7) == 0) {
                    char target_user[MAX_USERNAME];
                    char private_msg[MAX_MESSAGE];
                    if (sscanf(input_buffer + 7, "%s %[^\n]", target_user, private_msg) >= 2) {
                        if (send_private_message(&session, target_user, private_msg)) {
                            get_timestamp(timestamp, sizeof(timestamp));
                            save_message_to_db(&session, timestamp, session.username, target_user, "PRIVATE", private_msg);
                        }
                    } else {
                        printf(COLOR_RED "Usage: /prive <user> <message>\n" COLOR_RESET);
                    }
                    display_input_prompt(&session);
                }
                else if (strcmp(input_buffer, "/silence") == 0) {
                    session.silent_mode = !session.silent_mode;
                    print_notification("system", session.silent_mode ? "Mode silencieux activé" : "Mode silencieux désactivé");
                    display_input_prompt(&session);
                }
                else if (strcmp(input_buffer, "/effacer") == 0) {
                    system(CLEAR_SCREEN);
                    print_main_banner();
                    printf(COLOR_CYAN "Écran effacé. Bon retour " COLOR_RESET);
                    print_colored_username(session.username);
                    printf(COLOR_CYAN "!\n\n" COLOR_RESET);
                    display_input_prompt(&session);
                }
                else {
                    printf(COLOR_RED "Commande inconnue. Tapez /aide\n" COLOR_RESET);
                    display_input_prompt(&session);
                }
            }
            // MESSAGE PRIVÉ avec @
            else if (input_buffer[0] == '@') {
                char target_user[MAX_USERNAME];
                char private_msg[MAX_MESSAGE];
                if (sscanf(input_buffer + 1, "%s %[^\n]", target_user, private_msg) >= 2) {
                    if (send_private_message(&session, target_user, private_msg)) {
                        get_timestamp(timestamp, sizeof(timestamp));
                        save_message_to_db(&session, timestamp, session.username, target_user, "PRIVATE", private_msg);
                    }
                } else {
                    printf(COLOR_RED "Usage: @user message\n" COLOR_RESET);
                }
                display_input_prompt(&session);
            }
            // MESSAGE PUBLIC
            else {
                get_timestamp(timestamp, sizeof(timestamp));
                /*printf(COLOR_CYAN "==> [%s] " COLOR_RESET, timestamp);
                print_colored_username(session.username);
                printf(": %s\n", input_buffer);*/
                
                save_message_to_db(&session, timestamp, session.username, "ALL", "PUBLIC", input_buffer);
                
                snprintf(message_buffer, sizeof(message_buffer), "MESSAGE|%s|%s", session.username, input_buffer);
                sendto(session.sock, message_buffer, strlen(message_buffer), 0,
                      (struct sockaddr*)&session.multicast_addr, sizeof(session.multicast_addr));
                
                display_input_prompt(&session);
            }
        } else {
            display_input_prompt(&session);
        }
        
        // Réinitialiser le buffer
        input_pos = 0;
        memset(input_buffer, 0, sizeof(input_buffer));
    }
    else if (ch == 127 || ch == 8) {  // Backspace
        if (input_pos > 0) {
            input_pos--;
            input_buffer[input_pos] = '\0';
            printf("\b \b");
            fflush(stdout);
        }
    }
    else if (ch >= 32 && ch < 127) {  // Caractère imprimable
        if (input_pos < MAX_MESSAGE - 1) {
            input_buffer[input_pos++] = ch;
            printf("%c", ch);
            fflush(stdout);
        }
    }
}


        static time_t last_timeout_check = 0;
        time_t now = time(NULL);
        if (now - last_heartbeat >= HEARTBEAT_INTERVAL) {
            send_heartbeat(&session);
            last_heartbeat = now;
        }

        if (now - last_timeout_check >= 5){
            check_user_timeouts(&session);
            last_timeout_check = now;
        }
    }
    
    cleanup_and_exit(&session);
    
    return 0;
}