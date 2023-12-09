// SPDX-License-Identifier: Apache-2.0

#ifndef __RABIN_CHUNKER_HH__
#define __RABIN_CHUNKER_HH__

#include "chunker.hh"
#include <cstdint>
#include <cstdlib>
#include <glog/logging.h>
#include <vector>

class RabinChunker : public DedupChunker {
public:
  RabinChunker();

  ~RabinChunker();

  /**
   * All the info needed for a rabin polynomial list, namely the start position
   * in the file, the length of the block, the checksum, and the next polynomial
   */
  struct rabin_polynomial {
    uint64_t start;
    uint16_t length;
    uint64_t polynomial;
    struct rabin_polynomial *next_polynomial;
  };

  /*
   * Struct used to keep track of rabin polynomials for blocks of memory,
   * since the blocks may or may not end on a boundary, we have to save the
   * current rolling checksum, length, and block checksum so that we can
   * pick up were we left off
   */
  struct rabin_block_info {
    struct rabin_polynomial *head;
    struct rabin_polynomial *tail;
    uint64_t total_bytes_read;
    unsigned int window_pos;
    char cur_poly_finished;
    char *cur_window_data;
    uint64_t cur_roll_checksum;
    uint64_t cur_block_checksum;
    uint64_t cur_roll_offset;
  };

  // change averge_rabin_block_size
  void change_average_rabin_block_size(int increment_mode);

  // add a new rabin fingerprint
  struct rabin_polynomial *gen_new_polynomial(struct rabin_polynomial *tail,
                                              uint64_t total_len,
                                              uint64_t length,
                                              uint64_t rab_sum);

  // Deallocates the entire fingerprint list
  void free_rabin_fingerprint_list(struct rabin_polynomial *head);

  // init new block to save all the metadata
  struct rabin_block_info *init_empty_block();

  // read memory and generate a rabin fingerprint
  struct rabin_block_info *read_rabin_block(const void *buf, size_t size,
                                            struct rabin_block_info *cur_block);

  std::vector<unsigned long int> doChunk(const unsigned char *data,
                                         unsigned int len);

  /*
  int write_rabin_fingerprints_to_binary_file(FILE *file,struct rabin_polynomial
  *head); struct rabin_polynomial *read_rabin_polys_from_file_binary(FILE
  *file); void print_rabin_poly_to_file(FILE *out_file, struct rabin_polynomial
  *poly,int new_line); void print_rabin_poly_list_to_file(FILE *out_file, struct
  rabin_polynomial *poly); struct rabin_polynomial *get_file_rabin_polys(FILE
  *file_to_read);
  */
private:
  uint64_t rabin_polynomial_prime_;
  unsigned int rabin_sliding_window_size_;
  unsigned int rabin_polynomial_average_block_size_;
  unsigned int rabin_polynomial_max_block_size_;
  unsigned int rabin_polynomial_min_block_size_;
  rabin_block_info *rabin_info_;
  uint64_t *polynomial_lookup_buf_;
};

#endif