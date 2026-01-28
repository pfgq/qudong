/*
 * TearGame Example Application
 * 
 * Demonstrates how to use the TearGame kernel module
 * Compile: gcc -o example example.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Include user-space header */
#include "../include/teargame_user.h"

/* Magic string for authentication */
#define AUTH_MAGIC "MyApplication"

void print_usage(const char *prog)
{
    printf("TearGame Example Application\n");
    printf("Usage: %s <command> [args...]\n\n", prog);
    printf("Commands:\n");
    printf("  check               - Check if module is loaded\n");
    printf("  auth                - Authenticate with module\n");
    printf("  find <name>         - Find PID by process name\n");
    printf("  base <pid> <module> - Get module base address\n");
    printf("  read <pid> <addr> <size> - Read memory\n");
    printf("  touch <w> <h>       - Initialize touch device\n");
    printf("  tap <x> <y>         - Tap at position\n");
    printf("  swipe <x1> <y1> <x2> <y2> - Swipe\n");
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    const char *cmd = argv[1];
    
    /* Check if module is loaded */
    if (strcmp(cmd, "check") == 0) {
        if (tear_is_loaded()) {
            printf("TearGame module is loaded!\n");
            return 0;
        } else {
            printf("TearGame module is NOT loaded.\n");
            return 1;
        }
    }
    
    /* Authenticate */
    if (strcmp(cmd, "auth") == 0) {
        printf("Authenticating with module...\n");
        
        int ret = tear_auth(AUTH_MAGIC);
        if (ret == 0) {
            printf("Authentication successful!\n");
            return 0;
        } else {
            printf("Authentication failed: %d\n", ret);
            return 1;
        }
    }
    
    /* Find PID */
    if (strcmp(cmd, "find") == 0) {
        if (argc < 3) {
            printf("Usage: %s find <process_name>\n", argv[0]);
            return 1;
        }
        
        const char *name = argv[2];
        printf("Finding PID for '%s'...\n", name);
        
        int pid = tear_find_pid(name);
        if (pid > 0) {
            printf("Found PID: %d\n", pid);
            return 0;
        } else {
            printf("Process not found.\n");
            return 1;
        }
    }
    
    /* Get module base */
    if (strcmp(cmd, "base") == 0) {
        if (argc < 4) {
            printf("Usage: %s base <pid> <module_name>\n", argv[0]);
            return 1;
        }
        
        int pid = atoi(argv[2]);
        const char *module = argv[3];
        
        printf("Getting base of '%s' in PID %d...\n", module, pid);
        
        uint64_t base = tear_get_module_base(pid, module);
        if (base != 0) {
            printf("Module base: 0x%lx\n", base);
            return 0;
        } else {
            printf("Module not found.\n");
            return 1;
        }
    }
    
    /* Read memory */
    if (strcmp(cmd, "read") == 0) {
        if (argc < 5) {
            printf("Usage: %s read <pid> <addr> <size>\n", argv[0]);
            return 1;
        }
        
        int pid = atoi(argv[2]);
        uint64_t addr = strtoull(argv[3], NULL, 0);
        size_t size = atoi(argv[4]);
        
        if (size > 4096) size = 4096;
        
        uint8_t *buffer = malloc(size);
        if (!buffer) {
            printf("Failed to allocate buffer.\n");
            return 1;
        }
        
        printf("Reading %zu bytes from PID %d at 0x%lx...\n", size, pid, addr);
        
        int ret = tear_read(pid, addr, buffer, size);
        if (ret == 0) {
            printf("Read successful! First 16 bytes:\n");
            for (int i = 0; i < 16 && i < size; i++) {
                printf("%02x ", buffer[i]);
            }
            printf("\n");
            free(buffer);
            return 0;
        } else {
            printf("Read failed: %d\n", ret);
            free(buffer);
            return 1;
        }
    }
    
    /* Initialize touch device */
    if (strcmp(cmd, "touch") == 0) {
        int width = 1080, height = 2400;
        
        if (argc >= 4) {
            width = atoi(argv[2]);
            height = atoi(argv[3]);
        }
        
        printf("Initializing touch device %dx%d...\n", width, height);
        
        int ret = tear_touch_init(width, height);
        if (ret == 0) {
            printf("Touch device initialized!\n");
            return 0;
        } else {
            printf("Touch init failed: %d\n", ret);
            return 1;
        }
    }
    
    /* Tap */
    if (strcmp(cmd, "tap") == 0) {
        if (argc < 4) {
            printf("Usage: %s tap <x> <y>\n", argv[0]);
            return 1;
        }
        
        int x = atoi(argv[2]);
        int y = atoi(argv[3]);
        
        printf("Tapping at (%d, %d)...\n", x, y);
        
        int ret = tear_touch_tap(x, y, 50);
        if (ret == 0) {
            printf("Tap complete!\n");
            return 0;
        } else {
            printf("Tap failed: %d\n", ret);
            return 1;
        }
    }
    
    /* Swipe */
    if (strcmp(cmd, "swipe") == 0) {
        if (argc < 6) {
            printf("Usage: %s swipe <x1> <y1> <x2> <y2>\n", argv[0]);
            return 1;
        }
        
        int x1 = atoi(argv[2]);
        int y1 = atoi(argv[3]);
        int x2 = atoi(argv[4]);
        int y2 = atoi(argv[5]);
        
        printf("Swiping from (%d, %d) to (%d, %d)...\n", x1, y1, x2, y2);
        
        int ret = tear_touch_swipe(x1, y1, x2, y2, 20, 500);
        if (ret == 0) {
            printf("Swipe complete!\n");
            return 0;
        } else {
            printf("Swipe failed: %d\n", ret);
            return 1;
        }
    }
    
    printf("Unknown command: %s\n", cmd);
    print_usage(argv[0]);
    return 1;
}
