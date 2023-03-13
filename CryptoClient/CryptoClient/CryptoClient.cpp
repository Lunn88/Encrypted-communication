#include"CryptoClient.h"

void encrypt_blocks(string tmp) {

	int len = tmp.length();
	int blocks_num = len / (ONE_BLOCK_NUM + 1) + 2;
	int fill;
	encrypt_inform_block(len, blocks_num, fill);

	// strcat
	for (int i = 0; i < tmp.length(); i++) {
		buff[ONE_BLOCK_NUM + i] = tmp[i];
	}

	if (fill > 0) {
		for (int i = 0; i < fill; i++) {
			buff[ONE_BLOCK_NUM + len + i] = fill;
		}
	}

	encrypt_msg_blocks(blocks_num);
}

void decode_block(char* tmp) {
	int blocks_num, fill;
	decrypt_inform_block(tmp, blocks_num, fill);
	decrypt_msg_blocks(tmp, blocks_num, fill);
}

void mySend() {
	string tmp;
	bool first = true;
	while (true) {
		if (first) {
			first = false;
			cin.get();
		}
		getline(cin, tmp);
		ZeroMemory(buff, BUFF_SIZE);
		encrypt_blocks(tmp);
		send(serverSocket, buff, BUFF_SIZE, NULL);
	}
}

int main() {
	int len = 0;
	init();
	send_en();

	recv_set_aeskey();
	keySchedual = generateKeys(aes_key);

	CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)mySend, NULL, NULL, NULL);

	cout << "Plz input ID:";
	cin >> my_ID[0];
	my_ID[1] = '\0';
	others_ID[1] = ':';
	others_ID[2] = '\0';

	//接收服務器發來的數據並顯示
	char tmp[BUFF_SIZE];

	while (true) {
		ZeroMemory(tmp, BUFF_SIZE);
		recv(serverSocket, tmp, BUFF_SIZE, NULL);
		decode_block(tmp);
		t = time(0);
		strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&t));
		outtextxy(1, len * 20, timeStr);
		outtextxy(140, len * 20, others_ID);
		outtextxy(155, len * 20, tmp);
		len++;
	}

	closesocket(serverSocket);
	WSACleanup();
}