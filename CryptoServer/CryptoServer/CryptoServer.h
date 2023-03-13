#include<WinSock2.h>
#include<WS2tcpip.h>
#include<time.h>
#include"AES.h"
#include"RSA.h"

#pragma comment (lib, "ws2_32.lib")
#pragma warning (disable : 4996)

#define ONE_BLOCK_NUM 16
#define BUFF_SIZE 100

class client {
public:
	SOCKET clientSocket;
	char ID;
};

char* ID = new char[10];
char buff[BUFF_SIZE];
client clients[10];
int clientCount = 0;
time_t t;
char timeStr[20];
int client_n[10];
array<int, ONE_BLOCK_NUM> aes_key = {};
array<array<int, ONE_BLOCK_NUM>, 11> keySchedual;
char c_key[33];

int r;
SOCKET serverSocket;

pair<long int, long int> get_en(char buff[]) {
	char* tmp = new char[BUFF_SIZE];
	ZeroMemory(tmp, BUFF_SIZE);
	for (int i = 0; i < 5; i++) {
		tmp[i] = buff[i];
	}
	long int e; 
	sscanf(tmp, "%d", &e);
	ZeroMemory(tmp, BUFF_SIZE);
	for (int i = 5; i < strlen(buff); i++) {
		tmp[i - 5] = buff[i];
	}
	long int n;
	sscanf(tmp, "%d", &n);
	return { e, n };
}

void set_send_aeskey(long int e, long n, SOCKET clientSocket) {
	for (int t = 0, j = 0; t < 32; t += 2, j++) {
		char a = c_key[t];
		char b = c_key[t + 1];
		char tmp[3] = { a, b, '\0' };
		int h = stoi(tmp, 0, 16);
		aes_key[j] = h;
		h = RSA_Encrypt(h, e, n);
		char s[20];
		ZeroMemory(s, 20);
		snprintf(s, sizeof(s), "%d", h);
		send(clientSocket, s, 20, NULL);
		//Sleep(100);
	}
}

void init() {
	t = time(NULL);
	strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&t));
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		cout << timeStr << ' ' << "WSA Startup fail: " << GetLastError() << endl;
		exit(-1);
	}
	cout << timeStr << ' ' << "WSA Startup." << endl;

	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (SOCKET_ERROR == serverSocket) {
		cout << timeStr << ' ' << "Create socket fail:" << GetLastError() << endl;
		WSACleanup();

		exit(-1);
	}
	cout << timeStr << ' ' << "socket created." << endl;

	SOCKADDR_IN addr = { 0 };
	addr.sin_family = AF_INET;
	struct in_addr s;
	addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(443);

	r = bind(serverSocket, (sockaddr*)&addr, sizeof addr);
	if (r == -1) {
		cout << timeStr << ' ' << "Fail binding:" << GetLastError() << endl;
		closesocket(serverSocket);
		WSACleanup();
		exit(-1);
	}
	cout << timeStr << ' ' << "Bind successfully!" << endl;

	r = listen(serverSocket, 10);
	if (r == -1) {
		cout << timeStr << ' ' << "Fail listening:" << GetLastError() << endl;
		closesocket(serverSocket);
		WSACleanup();
		exit(-1);
	}
	cout << timeStr << ' ' << "start listening..." << endl;
}

int k = 0;
void decrypt_inform_block(char* tmp) {
	array<int, ONE_BLOCK_NUM> input;
	for (int i = 0; i < ONE_BLOCK_NUM; i++) {
		input[i] = tmp[i];
		if (input[i] < 0) {
			input[i] += 256;
		}
	}
	array<array<int, 4>, 4> cipher_text_block = inputToState(input);
	array<array<int, 4>, 4> plain_text_block = decryptBlock(cipher_text_block, keySchedual);
	array<int, ONE_BLOCK_NUM> output = stateToOutput(plain_text_block);
	clients[k].ID = output[2];
}