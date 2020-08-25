#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <iostream>
#include <thread>

using namespace std;

void usage() {
	cout << "syntax: ts <port>\n";
	cout << "sample: ts [-e] 1234\n";
}

struct Param {
	bool echo{false};
	uint16_t port{0};

	bool parse(int argc, char* argv[]) {
		if (argc < 2) return false;
		bool portExist = false;
		for (int i = 1; i < argc; i++) {
			if (strcmp(argv[i], "-e") == 0) {
				echo = true;
				continue;
			}
			port = stoi(argv[i]);
			portExist = true;
		}
		return portExist;
	}
} param;

void recvThread(int sd) {
	cout << "BOB9 DDoS Target Server connected\n";

	
	static const int BUFSIZE = 65536;
	char buf[BUFSIZE];
	while (true) {
		ssize_t res = recv(sd, buf, BUFSIZE - 1, 0);
		if (res == 0 || res == -1) {
			fprintf(stderr, "recv return %ld\n", res);
			perror("recv");
			break;
		}
		buf[res] = '\0';
		cout << buf << endl;
		if (param.echo) {
			res = send(sd, buf, res, 0);
			if (res == 0 || res == -1) {
				fprintf(stderr, "send return %ld\n", res);
				perror("send");
				break;
			}
		}
	}
	cout << "disconnected\n";
    close(sd);
}

int main(int argc, char* argv[]) {

	if (!param.parse(argc, argv)) {
		usage();
		return -1;
	}

	int sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd == -1) {
		perror("socket");
		return -1;
	}

	int optval = 1;
	int res = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
	if (res == -1) {
		perror("setsockopt");
		return -1;
	}
	
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(param.port);

	res = bind(sd, (struct sockaddr *)&addr, sizeof(addr));
	if (res == -1) {
		perror("bind");
		return -1;
	}

	res = listen(sd, 5);
	if (res == -1) {
		perror("listen");
		return -1;
	}

	while (true) {
		struct sockaddr_in cli_addr;
		socklen_t len = sizeof(cli_addr);
		int cli_sd = accept(sd, (struct sockaddr *)&cli_addr, &len);
		if (cli_sd == -1) {
			perror("accept");
			break;
		}
		thread* t = new thread(recvThread, cli_sd);
		t->detach();
	}
	close(sd);
}
