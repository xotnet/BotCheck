#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "sha256.h"

/*

Low level protocol bot check.

Checking for a bot is done with proof of work. Client needs to find
sha256 hash starting with 0, 1, 2 or 4. This implementation allows you to check the legality
of connection. To bypass this check the attacker must have very large computing resources.
Also this check method allows dont keep blocked IP's, check user-agent or system which
can be spoofed.
Hard level is the number of characters equal to the beginning of the hash.

Easy level: 6
Normal level: 8
Hard level: 10

*/

int char_count(char *str) {
  int count = 0;
  while (*str != '\0') {
    count++;
    str++;
  }
  return count;
}

int get_random_number() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    srand(ts.tv_nsec ^ getpid());
    return rand();
}

void genRandomStr(char* out, int len) {
	srand(time(NULL));
	char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	for(int i = 0; i<len; i++) {
		out[i] = alphabet[get_random_number()%62];
	}
}

void genBotCheckTask(char* taskOutput /*64 characters*/, int hardLevel) {
	int finalHardLevel = hardLevel * 1;
	char begTask[4];
	genRandomStr(begTask, 4);
	strcpy(taskOutput, begTask);
	taskOutput[4] = '|';
	char hlStr[16];
	sprintf(hlStr,"%d", finalHardLevel);
	strcpy(taskOutput+5, hlStr);
	int charC = char_count(taskOutput);
	taskOutput[charC] = '|';
	taskOutput[charC+1] = '\0';
}

void passBotCheck(char* task, char* solution /*16 characters*/) {
	char base[20];
	char hardLVLStr[8];
	int i = 0;
	for(;*(task+i) != '|' && *(task+i) != 0; i++) {
		base[i] = *(task+i);
	} base[i] = '\0'; i++;
	for(int p = 0; *(task+i) != '|' && *(task+i) != 0; i++) {
		hardLVLStr[p] = *(task+i);
		p++;
	}
	int hardLevel = atoi(hardLVLStr);

	// power proof bot check passing
	char sha256Hex[65];
	int x = 0;
	unsigned long int index = 0;
	int baseLen = char_count(base);
	while (1) {
		sprintf(base+baseLen,"%ld", index);
		sha256_easy_hash_hex(base, char_count(base), sha256Hex);
		sha256Hex[64] = '\0';
    //printf("%s\n", sha256Hex);
		while (1) {
			if (sha256Hex[x] == '0' || sha256Hex[x] == '1' || sha256Hex[x] == '2' || sha256Hex[x] == '4') {
				x++;
			}
			else {break;}

			if (x == hardLevel) {
				sprintf(solution,"%ld", index);
				return;
			}
		}
		x = 0;
		index++;
	}
}

unsigned short int confirmBotCheckTask(char* task, char* solution) {
	char base[20];
	char hardLVLStr[4];
	int i = 0;
	for(;*(task+i) != '|' && *(task+i) != 0; i++) {
		base[i] = *(task+i);
	} base[i] = '\0'; i++;
	for(int p = 0; *(task+i) != '|' && *(task+i) != 0; i++) {
		hardLVLStr[p] = *(task+i);
		p++;
	}
	int hardLevel = *hardLVLStr - '0';
	i++;
	char sha256Hex[65];
	strcpy(base+char_count(base), solution);
	sha256_easy_hash_hex(base, char_count(base), sha256Hex);
	int x = 0;
  sha256Hex[64] = '\0';
	while (1) {
		if (sha256Hex[x] == '0' || sha256Hex[x] == '1' || sha256Hex[x] == '2' || sha256Hex[x] == '4') {
			x++;
		}
		else {break;}

		if (x == hardLevel) {
			return 1; // Bot check passed successfully!
		}
	}
	return 0; // This is bot :(
}