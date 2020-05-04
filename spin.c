#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char *argv[])
{
	if (argc != 3) {
		fprintf(stderr, "usage: %s spin-loops sleep-us\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	long spin_loops = strtol(argv[1], NULL, 10);
	long sleep_us   = strtol(argv[2], NULL, 10);

	struct timespec request = {
		.tv_sec = 0,
		.tv_nsec = sleep_us * 1000,
	};

	while (1) {
		long sum = 0;
		for (long l = 0; l <= spin_loops; ++l)
			sum += 1;
		clock_nanosleep(CLOCK_MONOTONIC, 0, &request, NULL);
	}
}
