#include "botCheck.h"
int main() {
	char botCheckTask[64];
	genBotCheckTask(botCheckTask, 8);
	printf("%s\n", botCheckTask);

	char solution[16];
	passBotCheck(botCheckTask, solution);
	printf("Solution is: %s\n", solution);

	if (confirmBotCheckTask(botCheckTask, solution) == 1) {
		printf("Client is't bot! :)\n");
	} else {
		printf("Client is bot! :(\n");
	}
}