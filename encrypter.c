#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <mta_rand.h>
#include <mta_crypt.h>
#include <time.h>
#include <sys/select.h>

#define CONFIG_FILE "/mnt/mta/config.txt"
#define ENCRYPTER_PIPE "/mnt/mta/encrypter_pipe"
#define MAX_PASSWORD_LEN 256
#define MAX_KEY_LEN 64
#define MAX_DECRYPTERS 10

typedef struct {
    char pipe_name[128];
    int active;
    time_t last_seen;
} decrypter_info_t;

typedef struct {
    char type[16];  // "SUBSCRIBE" or "RESULT"
    char pipe_name[128];
    char data[MAX_PASSWORD_LEN];
    unsigned int data_len;
} message_t;

char plain_password[MAX_PASSWORD_LEN];
char key[MAX_KEY_LEN];
char encrypted[MAX_PASSWORD_LEN];
unsigned int encrypted_len = 0;
unsigned int password_len = 0;
unsigned int key_len = 0;

decrypter_info_t decrypters[MAX_DECRYPTERS];
int decrypter_count = 0;

// Track current password to avoid processing stale results
char current_password[MAX_PASSWORD_LEN];
unsigned int current_password_len = 0;
time_t password_generation_time = 0;

MTA_CRYPT_RET_STATUS MTA_generate_random_key(char *key, int length) {
    if (!key || length <= 0) return MTA_CRYPT_RET_ERROR;
    MTA_get_rand_data(key, length);
    return MTA_CRYPT_RET_OK;
}

MTA_CRYPT_RET_STATUS MTA_generate_random_password(char *password, int length) {
    if (!password || length <= 0) return MTA_CRYPT_RET_ERROR;

    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    int charset_len = strlen(charset);

    for (int i = 0; i < length; ++i) {
        char rand_char = MTA_get_rand_char();
        password[i] = charset[(unsigned char)rand_char % charset_len];
    }
    password[length] = '\0';
    return MTA_CRYPT_RET_OK;
}

void log_message(const char* level, const char* message) {
    FILE *log_file = fopen("/var/log/encrypter.log", "a");
    if (log_file) {
        time_t now = time(NULL);
        char* time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0';  // Remove newline
        fprintf(log_file, "[%s] [%s] %s\n", time_str, level, message);
        fclose(log_file);
    }
    printf("[ENCRYPTER] [%s] %s\n", level, message);
    fflush(stdout);
}

void read_config() {
    FILE *file = fopen(CONFIG_FILE, "r");
    if (!file) {
        log_message("ERROR", "Failed to open config file");
        exit(1);
    }
    
    if (fscanf(file, "%u %u", &password_len, &key_len) != 2) {
        log_message("ERROR", "Invalid config file format");
        fclose(file);
        exit(1);
    }
    fclose(file);
    
    if (password_len % 8 != 0 || password_len > MAX_PASSWORD_LEN || key_len > MAX_KEY_LEN) {
        log_message("ERROR", "Invalid password/key length");
        exit(1);
    }
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Config loaded: password_len=%u, key_len=%u", 
             password_len, key_len);
    log_message("INFO", log_msg);
}

void generate_and_encrypt_password() {
    if (MTA_generate_random_password(plain_password, password_len) != MTA_CRYPT_RET_OK) {
        log_message("ERROR", "Failed to generate password");
        exit(1);
    }
    
    if (MTA_generate_random_key(key, key_len) != MTA_CRYPT_RET_OK) {
        log_message("ERROR", "Failed to generate key");
        exit(1);
    }
    
    if (MTA_encrypt(key, key_len, plain_password, password_len, encrypted, &encrypted_len) != MTA_CRYPT_RET_OK) {
        log_message("ERROR", "Encryption failed");
        exit(1);
    }
    
    // Update current password tracking
    memcpy(current_password, plain_password, password_len);
    current_password_len = password_len;
    password_generation_time = time(NULL);
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Generated new password: %.*s", password_len, plain_password);
    log_message("INFO", log_msg);
}

void send_encrypted_to_decrypter(const char* pipe_name) {
    char log_msg[256];
    
    // Try multiple times to open the pipe
    int fd = -1;
    for (int retry = 0; retry < 5; retry++) {
        fd = open(pipe_name, O_WRONLY | O_NONBLOCK);
        if (fd != -1) break;
        
        struct timespec ts = {0, 50 * 1000 * 1000}; // 50ms
        nanosleep(&ts, NULL);
    }
    
    if (fd == -1) {
        if (errno != ENXIO) { // ENXIO means no reader - this is expected sometimes
            snprintf(log_msg, sizeof(log_msg), "Failed to open pipe %s: %s", pipe_name, strerror(errno));
            log_message("WARNING", log_msg);
        }
        return;
    }
    
    // Send data in order: password_len, key_len, encrypted_len, key, encrypted_data
    ssize_t written = 0;
    ssize_t result;
    
    result = write(fd, &password_len, sizeof(password_len));
    if (result > 0) written += result;
    
    result = write(fd, &key_len, sizeof(key_len));
    if (result > 0) written += result;
    
    result = write(fd, &encrypted_len, sizeof(encrypted_len));
    if (result > 0) written += result;
    
    result = write(fd, key, key_len);
    if (result > 0) written += result;
    
    result = write(fd, encrypted, encrypted_len);
    if (result > 0) written += result;
    
    size_t expected_size = sizeof(password_len) + sizeof(key_len) + sizeof(encrypted_len) + key_len + encrypted_len;
    
    if ((size_t)written == expected_size) {
        snprintf(log_msg, sizeof(log_msg), "Sent encrypted password to %s", pipe_name);
        log_message("INFO", log_msg);
    } else {
        snprintf(log_msg, sizeof(log_msg), "Partial write to pipe %s: wrote %zd of %zu bytes", 
                 pipe_name, written, expected_size);
        log_message("WARNING", log_msg);
    }
    
    close(fd);
}

void broadcast_new_password() {
    log_message("INFO", "Broadcasting new password to all decrypters");
    
    // Add a delay to ensure all decrypters are ready
    struct timespec ts = {0, 300 * 1000 * 1000}; // 300 milliseconds
    nanosleep(&ts, NULL);
    
    for (int i = 0; i < decrypter_count; i++) {
        if (decrypters[i].active) {
            send_encrypted_to_decrypter(decrypters[i].pipe_name);
        }
    }
}

void handle_subscription(const message_t* msg) {
    if (decrypter_count >= MAX_DECRYPTERS) {
        log_message("ERROR", "Max decrypters reached");
        return;
    }
    
    // Check if this decrypter is already registered
    for (int i = 0; i < decrypter_count; i++) {
        if (strcmp(decrypters[i].pipe_name, msg->pipe_name) == 0) {
            decrypters[i].active = 1;
            decrypters[i].last_seen = time(NULL);
            log_message("INFO", "Decrypter re-registered");
            
            // Send current password to re-registered decrypter
            send_encrypted_to_decrypter(msg->pipe_name);
            return;
        }
    }
    
    strcpy(decrypters[decrypter_count].pipe_name, msg->pipe_name);
    decrypters[decrypter_count].active = 1;
    decrypters[decrypter_count].last_seen = time(NULL);
    decrypter_count++;
    
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "New decrypter subscribed: %s (total: %d)", 
             msg->pipe_name, decrypter_count);
    log_message("INFO", log_msg);
    
    // Wait a bit for the decrypter to be ready
    struct timespec ts = {0, 300 * 1000 * 1000}; // 300 milliseconds
    nanosleep(&ts, NULL);
    
    // Send current encrypted password to new decrypter
    send_encrypted_to_decrypter(msg->pipe_name);
}

void handle_result(const message_t* msg) {
    char log_msg[256];
    snprintf(log_msg, sizeof(log_msg), "Received result from %s: %.*s", 
             msg->pipe_name, msg->data_len, msg->data);
    log_message("INFO", log_msg);
    
    // Update last seen time for this decrypter
    for (int i = 0; i < decrypter_count; i++) {
        if (strcmp(decrypters[i].pipe_name, msg->pipe_name) == 0) {
            decrypters[i].last_seen = time(NULL);
            break;
        }
    }
    
    // Check if this is a valid result for the current password
    if (msg->data_len == current_password_len && 
        memcmp(msg->data, current_password, current_password_len) == 0) {
        
        snprintf(log_msg, sizeof(log_msg), "Password cracked successfully by %s!", msg->pipe_name);
        log_message("SUCCESS", log_msg);
        
        // Generate new password and broadcast
        generate_and_encrypt_password();
        broadcast_new_password();
    } else {
        // Check if this is a stale result (from previous password)
        time_t now = time(NULL);
        if (now - password_generation_time > 2) {  // Allow 2 second grace period
            snprintf(log_msg, sizeof(log_msg), "Stale password result ignored from %s", msg->pipe_name);
            log_message("INFO", log_msg);
        } else {
            snprintf(log_msg, sizeof(log_msg), "Invalid password received from %s", msg->pipe_name);
            log_message("INFO", log_msg);
        }
    }
}

int main() {
    log_message("INFO", "Starting encrypter");
    
    if (MTA_crypt_init() != MTA_CRYPT_RET_OK) {
        log_message("ERROR", "Failed to init MTA crypto library");
        exit(1);
    }
    
    read_config();
    generate_and_encrypt_password();
    
    // Create encrypter pipe
    unlink(ENCRYPTER_PIPE);
    if (mkfifo(ENCRYPTER_PIPE, 0666) == -1) {
        log_message("ERROR", "Failed to create encrypter pipe");
        exit(1);
    }
    
    log_message("INFO", "Waiting for decrypters...");
    
   while (1) {
    // Open pipe for reading
    int fd = open(ENCRYPTER_PIPE, O_RDONLY);
    if (fd == -1) {
        char log_msg[256];
        snprintf(log_msg, sizeof(log_msg), "Failed to open encrypter pipe: %s", strerror(errno));
        log_message("ERROR", log_msg);
        sleep(1);
        continue;
    }

    // Dummy open for writing to prevent blocking if no writers exist
    int dummy_fd = open(ENCRYPTER_PIPE, O_WRONLY | O_NONBLOCK);

    log_message("DEBUG", "Pipe opened for reading");
        
        // Keep reading messages until pipe is closed
        while (1) {
            message_t msg;
            ssize_t bytes_read = read(fd, &msg, sizeof(msg));
            
            if (bytes_read == sizeof(msg)) {
                if (strcmp(msg.type, "SUBSCRIBE") == 0) {
                    handle_subscription(&msg);
                } else if (strcmp(msg.type, "RESULT") == 0) {
                    handle_result(&msg);
                } else {
                    char log_msg[256];
                    snprintf(log_msg, sizeof(log_msg), "Unknown message type: %s", msg.type);
                    log_message("WARNING", log_msg);
                }
            } else if (bytes_read == 0) {
                // EOF - all writers have closed their end
                log_message("DEBUG", "All writers closed - reopening pipe");
                break;
            } else if (bytes_read > 0) {
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg), "Received incomplete message: %zd bytes", bytes_read);
                log_message("WARNING", log_msg);
            } else {
                // Error reading
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg), "Error reading from pipe: %s", strerror(errno));
                log_message("ERROR", log_msg);
                break;
            }
        }
        
        close(fd);
        if (dummy_fd != -1) close(dummy_fd);

        
        // Small delay before reopening
        struct timespec ts = {0, 100 * 1000 * 1000}; // 100 milliseconds
        nanosleep(&ts, NULL);
    }
    
    log_message("INFO", "Encrypter shutting down");
    unlink(ENCRYPTER_PIPE);
    return 0;
}