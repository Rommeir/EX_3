#define _XOPEN_SOURCE 700
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <sys/select.h>
#include <mta_rand.h>
#include <mta_crypt.h>

#define MAX_PASSWORD_LEN 256
#define MAX_KEY_LEN 64
#define ENCRYPTER_PIPE "/mnt/mta/encrypter_pipe"
#define DECRYPTER_PIPE_PREFIX "/mnt/mta/decrypter_pipe_"
#define SHUTDOWN_PIPE_PREFIX "/mnt/mta/decrypter_shutdown_"
#define STARTUP_DELAY 2

typedef struct {
    char type[16];
    char pipe_name[128];
    char data[MAX_PASSWORD_LEN];
    unsigned int data_len;
} message_t;

char key[MAX_KEY_LEN];
char decrypted[MAX_PASSWORD_LEN];
unsigned int decrypted_len = 0;
char my_pipe[128];
char shutdown_pipe[128];
char decrypter_id[32];
int my_id;

void log_message(const char* level, const char* message) {
    char log_file_path[256];
    snprintf(log_file_path, sizeof(log_file_path), "/var/log/decrypter_%d.log", my_id);
    FILE *log_file = fopen(log_file_path, "a");
    if (log_file) {
        time_t now = time(NULL);
        char* time_str = ctime(&now);
        time_str[strlen(time_str)-1] = '\0';
        fprintf(log_file, "[%s] [%s] %s\n", time_str, level, message);
        fclose(log_file);
    }
    printf("[DECRYPTER_%d] [%s] %s\n", my_id, level, message);
    fflush(stdout);
}

int check_shutdown_request() {
    int fd = open(shutdown_pipe, O_RDONLY | O_NONBLOCK);
    if (fd != -1) {
        char buffer[1];
        if (read(fd, buffer, 1) > 0) {
            close(fd);
            return 1;
        }
        close(fd);
    }
    return 0;
}

void wait_for_encrypter() {
    log_message("INFO", "Waiting for encrypter to be ready...");
    while (access(ENCRYPTER_PIPE, F_OK) == -1) {
        if (check_shutdown_request()) exit(0);
        sleep(1);
    }
    sleep(STARTUP_DELAY);
    log_message("INFO", "Encrypter detected");
}

void send_subscription() {
    message_t msg = {0};
    strcpy(msg.type, "SUBSCRIBE");
    strcpy(msg.pipe_name, my_pipe);
    msg.data_len = 0;

    for (int retry = 0; retry < 10; retry++) {
        if (check_shutdown_request()) exit(0);
        int fd = open(ENCRYPTER_PIPE, O_WRONLY | O_NONBLOCK);
        if (fd != -1) {
            if (write(fd, &msg, sizeof(msg)) == sizeof(msg)) {
                close(fd);
                log_message("INFO", "Subscription sent");
                return;
            }
            close(fd);
        }
        sleep(1);
    }

    log_message("ERROR", "Failed to send subscription");
    exit(1);
}

void send_result(const char* password, unsigned int len) {
    message_t msg = {0};
    strcpy(msg.type, "RESULT");
    strcpy(msg.pipe_name, my_pipe);
    memcpy(msg.data, password, len);
    msg.data_len = len;

    for (int retry = 0; retry < 10; retry++) {  // Increased retries
        if (check_shutdown_request()) exit(0);
        int fd = open(ENCRYPTER_PIPE, O_WRONLY | O_NONBLOCK);
        if (fd != -1) {
            if (write(fd, &msg, sizeof(msg)) == sizeof(msg)) {
                close(fd);
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg), "Sent result: %.*s", len, password);
                log_message("INFO", log_msg);
                return;
            }
            close(fd);
        }
        struct timespec ts = {0, 200 * 1000 * 1000}; // Increased delay to 200ms
        nanosleep(&ts, NULL);
    }
    log_message("ERROR", "Failed to send result after retries");
}

int is_valid_password(const char* password, unsigned int len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (unsigned int i = 0; i < len; i++) {
        if (strchr(charset, password[i]) == NULL) return 0;
    }
    return 1;
}

void decrypt_password(unsigned int password_len, unsigned int key_len, unsigned int encrypted_len,
                      char* received_key, char* encrypted) {
    log_message("INFO", "Attempting decryption...");
    if (MTA_decrypt(received_key, key_len, encrypted, encrypted_len, decrypted, &decrypted_len) == MTA_CRYPT_RET_OK) {
        if (decrypted_len == password_len && is_valid_password(decrypted, decrypted_len)) {
            char success_msg[256];
            snprintf(success_msg, sizeof(success_msg), "Decryption success: %.*s", decrypted_len, decrypted);
            log_message("SUCCESS", success_msg);
            send_result(decrypted, decrypted_len);
        } else {
            log_message("ERROR", "Invalid decrypted result");
        }
    } else {
        log_message("ERROR", "Decryption failed");
    }
}

int find_available_id() {
    for (int id = 1; id <= 99; id++) {
        char pipe_path[128];
        snprintf(pipe_path, sizeof(pipe_path), "%s%d", DECRYPTER_PIPE_PREFIX, id);
        if (access(pipe_path, F_OK) == -1) return id;
    }
    return -1;
}

int read_encrypted_data_blocking(int fd, unsigned int* password_len, unsigned int* key_len,
                                unsigned int* encrypted_len, char* received_key, char* encrypted) {
    ssize_t bytes_read;
    
    // Read password length
    bytes_read = read(fd, password_len, sizeof(*password_len));
    if (bytes_read != sizeof(*password_len)) {
        if (bytes_read == 0) {
            log_message("DEBUG", "Pipe closed by writer");
        } else if (bytes_read > 0) {
            log_message("WARNING", "Partial read of password_len");
        }
        return 0;
    }
    
    // Read key length
    bytes_read = read(fd, key_len, sizeof(*key_len));
    if (bytes_read != sizeof(*key_len)) {
        if (bytes_read <= 0) {
            log_message("WARNING", "Failed to read key_len");
        }
        return 0;
    }
    
    // Read encrypted length
    bytes_read = read(fd, encrypted_len, sizeof(*encrypted_len));
    if (bytes_read != sizeof(*encrypted_len)) {
        if (bytes_read <= 0) {
            log_message("WARNING", "Failed to read encrypted_len");
        }
        return 0;
    }
    
    // Validate lengths
    if (*key_len > MAX_KEY_LEN || *encrypted_len > MAX_PASSWORD_LEN) {
        log_message("ERROR", "Invalid data lengths received");
        return 0;
    }
    
    // Read key
    bytes_read = read(fd, received_key, *key_len);
    if (bytes_read != *key_len) {
        if (bytes_read <= 0) {
            log_message("WARNING", "Failed to read key data");
        }
        return 0;
    }
    
    // Read encrypted data
    bytes_read = read(fd, encrypted, *encrypted_len);
    if (bytes_read != *encrypted_len) {
        if (bytes_read <= 0) {
            log_message("WARNING", "Failed to read encrypted data");
        }
        return 0;
    }
    
    return 1;
}

int main(int argc, char *argv[]) {
    if (argc == 2) {
        my_id = atoi(argv[1]);
    } else {
        my_id = find_available_id();
        if (my_id == -1) {
            fprintf(stderr, "No available ID\n");
            exit(1);
        }
    }

    snprintf(my_pipe, sizeof(my_pipe), "%s%d", DECRYPTER_PIPE_PREFIX, my_id);
    snprintf(shutdown_pipe, sizeof(shutdown_pipe), "%s%d", SHUTDOWN_PIPE_PREFIX, my_id);

    log_message("INFO", "Starting decrypter");
    unlink(shutdown_pipe);
    if (mkfifo(shutdown_pipe, 0666) == -1) {
        log_message("ERROR", "Failed to create shutdown pipe");
        exit(1);
    }

    wait_for_encrypter();
    unlink(my_pipe);
    if (mkfifo(my_pipe, 0666) == -1) {
        log_message("ERROR", "Failed to create my pipe");
        exit(1);
    }

    if (MTA_crypt_init() != MTA_CRYPT_RET_OK) {
        log_message("ERROR", "Failed to init crypto");
        exit(1);
    }

    send_subscription();
    log_message("INFO", "Ready for decryption");

    // Main loop - reopen pipe when needed
    while (1) {
        if (check_shutdown_request()) break;

        // Try to open the pipe for reading (blocking)
        int my_pipe_fd = open(my_pipe, O_RDONLY);
        if (my_pipe_fd == -1) {
            char log_msg[256];
            snprintf(log_msg, sizeof(log_msg), "Failed to open my pipe: %s", strerror(errno));
            log_message("ERROR", log_msg);
            sleep(1);
            continue;
        }

        log_message("DEBUG", "Pipe opened, waiting for data...");

        // Keep reading from pipe until it's closed
        while (1) {
            unsigned int password_len, key_len, encrypted_len;
            char received_key[MAX_KEY_LEN];
            char encrypted[MAX_PASSWORD_LEN];

            if (read_encrypted_data_blocking(my_pipe_fd, &password_len, &key_len, &encrypted_len, 
                                            received_key, encrypted)) {
                char log_msg[256];
                snprintf(log_msg, sizeof(log_msg), "Received encrypted data: pwd_len=%u, key_len=%u, enc_len=%u", 
                         password_len, key_len, encrypted_len);
                log_message("INFO", log_msg);
                
                decrypt_password(password_len, key_len, encrypted_len, received_key, encrypted);
            } else {
                // No more data or pipe closed
                log_message("DEBUG", "No more data from pipe");
                break;
            }
            
            // Small delay between processing attempts
            struct timespec ts = {0, 50 * 1000 * 1000}; // 50ms
            nanosleep(&ts, NULL);
        }

        close(my_pipe_fd);
        log_message("DEBUG", "Pipe closed, reopening...");
        
        // Small delay before reopening
        struct timespec ts = {0, 200 * 1000 * 1000}; // 200ms - optimized delay
        nanosleep(&ts, NULL);
    }

    log_message("INFO", "Shutting down");
    unlink(my_pipe);
    unlink(shutdown_pipe);
    return 0;
}