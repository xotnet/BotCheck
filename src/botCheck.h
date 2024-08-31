#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include "argon2.h"

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

const unsigned int HASHLEN = 32;
const unsigned int SALTLEN = 8;

const char charList[] = "0124abcd";
const uint16_t CHARLISTLEN = sizeof(charList);

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

void bin_to_hex(void* data, uint32_t len, char* out) {
    const char* lut = "0123456789abcdef";
    uint32_t i;
    for (i = 0; i < len; ++i){
        uint8_t c = ((const uint8_t*)data)[i];
        out[i*2] = lut[c >> 4];
        out[i*2 + 1] = lut[c & 15];
    }
}

void genRandomStr(char* out, int len) {
	srand(time(NULL));
	char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
	for(int i = 0; i<len; i++) {
		out[i] = alphabet[get_random_number()%62];
	}
}

void genBotCheckTask(char* taskOutput /*64 characters*/, int hardLevel) {
	/* | BaseToHash | HardLevel | Salt | */
	int finalHardLevel = hardLevel * 1;
	char begTask[4];
	genRandomStr(begTask, 4);
	strcpy(taskOutput, begTask);
	taskOutput[4] = '|';
	char hlStr[16];
	sprintf(hlStr,"%d", finalHardLevel);
	strcpy(taskOutput+5, hlStr);
	char salt[SALTLEN];
	genRandomStr(salt, SALTLEN);
	int charC = char_count(taskOutput);
	taskOutput[charC] = '|';
	strcpy(taskOutput+charC+1, salt);
	taskOutput[charC+SALTLEN+2] = '|';
	taskOutput[charC+SALTLEN+3] = '\0';
}

void passBotCheck(char* task, char* solution /*16 characters*/) {
	char base[20];
	char hardLVLStr[8];
	char salt[SALTLEN+1];
	int i = 0;
	for(;*(task+i) != '|' && *(task+i) != 0; i++) {
		base[i] = *(task+i);
	}
	base[i] = '\0';
	i++;
	for(int p = 0; *(task+i) != '|' && *(task+i) != 0; i++) {
		hardLVLStr[p] = *(task+i);
		p++;
	}
	i++;
	for(int p = 0; *(task+i) != '|' && *(task+i) != 0; i++) {
		salt[p] = *(task+i);
		p++;
	}
	salt[SALTLEN] = '\0';
	int hardLevel = atoi(hardLVLStr);

	// power proof bot check passing
	int x = 0;
	unsigned long int index = 0;
	int baseLen = char_count(base);
	uint8_t hash[HASHLEN];
	uint32_t t_cost = 4;
	uint32_t m_cost = (1<<12);
	uint32_t parallelism = 4;
	char hashHex[64];
	while (1) {
		sprintf(base+baseLen,"%ld", index);
		argon2i_hash_raw(t_cost, m_cost, parallelism, base, char_count(base), salt, SALTLEN, hash, HASHLEN);
		bin_to_hex(hash, 32, hashHex);
		hashHex[64] = '\0';
    //printf("%s\n", hashHex);
		while (1) {
			int o = 0;
			for (; o<CHARLISTLEN; o++) {
				if (charList[o] == hashHex[x]) {
					x++;
					break;
				}
			}
			if (o == CHARLISTLEN) {break;}

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
	char salt[SALTLEN+1];
	int i = 0;
	for(;*(task+i) != '|' && *(task+i) != 0; i++) {
		base[i] = *(task+i);
	}
	base[i] = '\0';
	i++;
	for(int p = 0; *(task+i) != '|' && *(task+i) != 0; i++) {
		hardLVLStr[p] = *(task+i);
		p++;
	} i++;
	for(int p = 0; *(task+i) != '|' && *(task+i) != 0; i++) {
		salt[p] = *(task+i);
		p++;
	}
	salt[SALTLEN] = '\0';
	int hardLevel = *hardLVLStr - '0';
	i++;
	char hashHex[65];
	strcpy(base+char_count(base), solution);
	uint8_t hash[HASHLEN];
	uint32_t t_cost = 4;
	uint32_t m_cost = (1<<12);
	uint32_t parallelism = 4;
	argon2i_hash_raw(t_cost, m_cost, parallelism, base, char_count(base), salt, SALTLEN, hash, HASHLEN);
	int x = 0;
  hashHex[64] = '\0';
	while (1) {
		int o = 0;
		for (; o<CHARLISTLEN; o++) {
			if (charList[o] == hashHex[x]) {
				x++;
				break;
			}
		}
		if (o == CHARLISTLEN) {break;}

		if (x == hardLevel) {
			return 1; // Bot check passed successfully!
		}
	}
	return 0; // This is bot :(
}