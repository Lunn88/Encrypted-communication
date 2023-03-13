#include <iostream>
#include <array>

using namespace std;

void print_1d_State(const array<int, 16>& e);
array<array<int, 4>, 4> inputToState(const array<int, 16>& input);
array<int, 16> stateToOutput(const array<array<int, 4>, 4>& state);

array<array<int, 4>, 4> keyToWords(const array<int, 16>& roundKey);
array<array<int, 4>, 4> transposeState(const array<array<int, 4>, 4>& state);

int multiply_by_2(const int v);
int multiply_by_3(int v);

int lookupByte(int& byte);
int invLookupByte(int& byte);
auto subBytes(const array<array<int, 4>, 4>& state);
auto unSubBytes(const array<array<int, 4>, 4>& state);

array<int, 4> shiftRow(const array<int, 4>& row, const int shift);
auto shiftRows(const array<array<int, 4>, 4>& state);
array<int, 4> unShiftRow(const array<int, 4>& row, const int shift);
auto unShiftRows(const array<array<int, 4>, 4>& state);

auto mixColumn(const array<int, 4>& stateColumn);
auto mixColumns(const array<array<int, 4>, 4>& state);
auto unMixColumns(const array<array<int, 4>, 4>& state);

array<int, 4> xorWords(const array<int, 4>& wordA, const array<int, 4>& wordB);
array<int, 4> subWord(const array<int, 4>& word);
array<int, 4> rotWord(const array<int, 4>& word);

auto addRoundKey(const array<array<int, 4>, 4>& state, const array<int, 16>& roundKey);

array<array<int, 16>, 11> generateKeys(const array<int, 16>& key);

array<array<int, 4>, 4> encryptBlock(const array<array<int, 4>, 4>& block, const array<array<int, 16>, 11> keySchedual);
array<array<int, 4>, 4> decryptBlock(const array<array<int, 4>, 4>& block, const array<array<int, 16>, 11> keySchedual);