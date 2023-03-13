#include"CryptoServer.h"

void communicate(int i) {
	char* tmp = new char[BUFF_SIZE];

	// get en
	recv(clients[i].clientSocket, buff, BUFF_SIZE, NULL);
	long int e, n;
	tie(e, n) = get_en(buff);

	set_send_aeskey(e, n, clients[i].clientSocket);

	while (true) {
		ZeroMemory(buff, BUFF_SIZE);
		r = recv(clients[i].clientSocket, buff, BUFF_SIZE, NULL);
		if(r > 0){
			for (int i = 0; i < clientCount; i++) {
				send(clients[i].clientSocket, buff, BUFF_SIZE, NULL);
			}
		}
	}
}

int main() {
	init();

	strcpy(c_key, gen_keys());
	keySchedual = generateKeys(aes_key);

	//接收客戶端連接
	for (int i = 0; i < 10; i++) {
		clients[i].clientSocket = accept(serverSocket, (sockaddr*)NULL, NULL);
		t = time(NULL);
		strftime(timeStr, sizeof(timeStr), "%Y-%m-%d %H:%M:%S", localtime(&t));
		if (r == -1) {
			cout << timeStr << ' ' << "Server crashed:" << GetLastError() << endl;
			closesocket(serverSocket);
			WSACleanup();
			system("pause");
			return -1;
		}
		cout << timeStr << ' ' << "new connection!" << endl;
		clientCount++;
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)communicate, (LPVOID)i, NULL, NULL);
	}

	closesocket(serverSocket);
	WSACleanup();
	return 0;
}