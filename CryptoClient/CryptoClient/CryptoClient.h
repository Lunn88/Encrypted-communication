#include<WinSock2.h>
#include<WS2tcpip.h>
#include<graphics.h>
#include<string>
#include<tuple>
#include"AES.h"
#include"RSA.h"

#define ONE_BLOCK_NUM 16
#define BUFF_SIZE 100

#pragma comment (lib, "ws2_32.lib")
#pragma warning (disable : 4996)

time_t t;
char timeStr[20];
SOCKET serverSocket;
char* my_ID = new char[2];
char* others_ID = new char[3];
char* buff = new char[BUFF_SIZE];
long int n, d;
array<int, ONE_BLOCK_NUM> aes_key;
array<array<int, ONE_BLOCK_NUM>, 11> keySchedual;

void encrypt_inform_block(int& len, int& blocks_num, int& fill) {
	if (len > ONE_BLOCK_NUM) {
		fill = 16 - len % 16;
	}
	else {
		fill = 16 - len;
	}
	ZeroMemory(buff, BUFF_SIZE);

	array<int, ONE_BLOCK_NUM> input;
	input[0] = blocks_num;
	input[1] = fill;
	input[2] = my_ID[0];
	for (int i = 3; i < ONE_BLOCK_NUM; i++) {
		input[i] = 13;
	}
	array<array<int, 4>, 4> plain_text_block = inputToState(input);
	array<array<int, 4>, 4> cipher_text_block = encryptBlock(plain_text_block, keySchedual);
	array<int, ONE_BLOCK_NUM> output = stateToOutput(cipher_text_block);
	for (int i = 0; i < ONE_BLOCK_NUM; i++) {
		buff[i] = output[i];
	}
}

void encrypt_msg_blocks(int blocks_num) {
	for (int num = 1; num < blocks_num; num++) {
		array<int, ONE_BLOCK_NUM> input;
		for (int i = num * ONE_BLOCK_NUM, j = 0; j < ONE_BLOCK_NUM; i++, j++) {
			input[j] = buff[i];
		}

		array<array<int, 4>, 4> plain_text_block = inputToState(input);
		array<array<int, 4>, 4> cipher_text_block = encryptBlock(plain_text_block, keySchedual);
		array<int, ONE_BLOCK_NUM> output = stateToOutput(cipher_text_block);
		for (int i = num * ONE_BLOCK_NUM, j = 0; j < ONE_BLOCK_NUM; i++, j++) {
			buff[i] = output[j];
		}
	}
}

void decrypt_inform_block(char* tmp, int& blocks_num, int& fill) {
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
	blocks_num = output[0];
	fill = output[1];
	others_ID[0] = output[2];
}

void decrypt_msg_blocks(char* tmp, int blocks_num, int fill) {
	for (int b = 1; b < blocks_num; b++) {
		array<int, ONE_BLOCK_NUM> input;
		for (int i = 0, j = b * ONE_BLOCK_NUM; i < ONE_BLOCK_NUM; i++, j++) {
			input[i] = tmp[j];
			if (input[i] < 0) {
				input[i] += 256;
			}
		}
		array<array<int, 4>, 4>cipher_text_block = inputToState(input);
		array<array<int, 4>, 4>plain_text_block = decryptBlock(cipher_text_block, keySchedual);
		array<int, ONE_BLOCK_NUM> output = stateToOutput(plain_text_block);
		for (int i = 0, j = (b - 1) * ONE_BLOCK_NUM; i < ONE_BLOCK_NUM; i++, j++) {
			if (output[i] != fill)
				tmp[j] = output[i];
			else {
				tmp[j] = '\0';
			}
		}
	}
}

void init() {

	t = time(0);
	strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&t));
	initgraph(400, 500, SHOWCONSOLE);

	// Startup WSA
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		cout << timeStr << ' ' << "WSA Startup fail: " << GetLastError() << endl;
		exit(-1);
	}
	cout << timeStr << ' ' << "WSA Startup!" << endl;

	// create socket
	serverSocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (SOCKET_ERROR == serverSocket) {
		cout << timeStr << ' ' << "Create socket fail:" << GetLastError() << endl;
		WSACleanup();
		exit(-1);
	}
	cout << timeStr << ' ' << "socket created." << endl;

	SOCKADDR_IN addr = { 0 };
	addr.sin_family = AF_INET;
	addr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");
	addr.sin_port = htons(443);

	// connect to server
	int r = connect(serverSocket, (sockaddr*)&addr, sizeof addr);
	if (r == -1) {
		cout << timeStr << ' ' << "Fail to connect to server:" << GetLastError() << endl;
		closesocket(serverSocket);
		WSACleanup();
		exit(-1);
	}
	cout << timeStr << ' ' << "Connect to server" << endl;
	cout << timeStr << ' ' << "Generating keys..." << endl;
}

void send_en() {
	long int p, q, e;
	tie(p, q) = gen_prime();
	tie(e, n) = get_pb_keys(p, q);
	d = get_pv_keys(p, q);
	char* tmpp = new char[20];
	ZeroMemory(tmpp, 20);
	itoa(e, tmpp, 10);
	string en = tmpp;
	en += itoa(n, tmpp, 10);
	send(serverSocket, en.c_str(), en.length(), NULL);
}

void recv_set_aeskey() {
	char* c_key = new char[20];
	for (int i = 0; i < 16; i++) {
		ZeroMemory(c_key, 20);
		int r = recv(serverSocket, c_key, 20, NULL);
		if (r > 0) {
			int h;
			sscanf(c_key, "%d", &h);
			h = RSA_Decrypt(h, d, n);
			aes_key[i] = h;
		}
	}
}