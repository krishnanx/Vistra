#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>

/*
    VISITRA SAFE TEST SAMPLE
    This program DOES NOT encrypt or delete files.
    It exists only to trigger YARA rules.
*/

/* --- Crypto indicators (strings only) --- */
void crypto_markers() {
    printf("AES\n");
    printf("RSA\n");
    printf("ChaCha20\n");
    printf("EVP_EncryptInit\n");
}

/* --- File traversal indicators --- */
void traversal_markers() {
    DIR *d;
    struct dirent *dir;
    d = opendir(".");
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            printf("%s\n", dir->d_name);
        }
        closedir(d);
    }

    rename("dummy.txt", "dummy.txt.locked");
    unlink("dummy.txt.locked");
}

/* --- Ransom indicators --- */
void ransom_note() {
    printf("Your files are encrypted\n");
    printf("Send bitcoin to wallet\n");
    printf("Pay via TOR: abcdef123456.onion\n");
    printf("Decrypt your files\n");
}

int main() {
    crypto_markers();
    traversal_markers();
    ransom_note();
    return 0;
}
