// SPDX-License-Identifier: Apache-2.0

#include <iostream>


#include "../../proxy/dedup/chunking/rabin_chunker.hh"
#include "../../proxy/dedup/chunking/rabin_constrants.hh"

using namespace std;

int main(int argc, char **argv) {

  RabinChunker *rbc = new RabinChunker();
  // std::string data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz1111122222abcdefghijklmnopqrstuvwxyz1111122222abcdefghijklmnopqrstuvwxyz";
  std::string data = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyz";
  std::cout << data.size() << std::endl;

  auto res = rbc->doChunk((unsigned char*)data.c_str(), data.size());

  for(auto t : res) std::cout << t << std::endl;
  return 0;
}