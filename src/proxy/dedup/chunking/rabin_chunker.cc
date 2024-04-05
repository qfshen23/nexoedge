// SPDX-License-Identifier: Apache-2.0
#include <iostream>
#include "rabin_chunker.hh"
#include "rabin_constrants.hh"

RabinChunker::RabinChunker()
    : rabin_polynomial_prime_(RABIN_POLYNOMIAL_REM),
      rabin_sliding_window_size_(RABIN_POLYNOMIAL_WIN_SIZE),
      rabin_polynomial_average_block_size_(RABIN_POLYNOMIAL_AVG_BLOCK_SIZE),
      rabin_polynomial_max_block_size_(RABIN_MAX_BLOCK_SIZE),
      rabin_polynomial_min_block_size_(RABIN_MIN_BLOCK_SIZE) {
  rabin_info_ = new rabin_block_info;
  if (rabin_info_ == nullptr) {
    LOG(ERROR)
        << "Could not initialize rabin polynomial info, out of memory!\n";
    return;
  }
  rabin_info_->head = 0;
  rabin_info_->tail = 0;
  rabin_info_->window_pos = 0;
  rabin_info_->total_bytes_read = 0;
  rabin_info_->cur_window_data = 0;
  rabin_info_->cur_roll_checksum = 0;
  rabin_info_->cur_roll_offset = 0;
  rabin_info_->cur_poly_finished = 0;
  rabin_info_->cur_window_data = 0;

  polynomial_lookup_buf_ = new uint64_t[RABIN_POLYNOMIAL_MAX_WIN_SIZE];

  if (polynomial_lookup_buf_ == nullptr) {
    LOG(ERROR) << "Could not initialize rabin polynomial lookup buffer, out of "
                  "memory!\n";
    return;
  }

  int index = 0;
  uint64_t curPower = 1;
  // Initialize the lookup values we will need later
  for (index = 0; index < RABIN_POLYNOMIAL_MAX_WIN_SIZE; index++) {
    // TODO check if max window size is a power of 2
    // and if so use shifters instead of multiplication
    polynomial_lookup_buf_[index] = curPower;
    curPower *= rabin_polynomial_prime_;
  }
}

RabinChunker::~RabinChunker() {
  delete[] polynomial_lookup_buf_;
  // ****** may be need to delete the linked-list here
  free_rabin_fingerprint_list(rabin_info_->head);
  delete rabin_info_;
}

/**
 * Modifies the average block size, checking to make sure it doesn't
 * go above the max or below the min
 */
void RabinChunker::change_average_rabin_block_size(int increment_mode) {
  if (increment_mode != 0 and
      rabin_polynomial_average_block_size_ < rabin_polynomial_max_block_size_) {
    rabin_polynomial_average_block_size_++;
  } else if (increment_mode == 0 and rabin_polynomial_average_block_size_ >
                                         rabin_polynomial_min_block_size_) {
    rabin_polynomial_average_block_size_--;
  }
}

/*
 * Generate a new fingerprint with the given info and add it to the tail
 */
struct RabinChunker::rabin_polynomial *
RabinChunker::gen_new_polynomial(struct rabin_polynomial *tail,
                                 uint64_t total_len, uint64_t length,
                                 uint64_t rab_sum) {
  struct rabin_polynomial *next =
      (rabin_polynomial *)malloc(sizeof(struct rabin_polynomial));

  if (next == nullptr) {
    LOG(ERROR) << "Could not allocate memory for rabin fingerprint record!\n";
    return nullptr;
  }

  if (tail != nullptr) {
    tail->next_polynomial = next;
  }

  next->next_polynomial = nullptr;
  next->start = total_len;
  next->length = 0;
  next->polynomial = rab_sum;

  return next;
}

/*
 * Deallocates the entire fingerprint list
 */
void RabinChunker::free_rabin_fingerprint_list(struct rabin_polynomial *head) {
  struct rabin_polynomial *cur_poly;
  struct rabin_polynomial *next_poly;

  cur_poly = head;

  while (cur_poly != nullptr) {
    next_poly = cur_poly->next_polynomial;
    free(cur_poly);
    cur_poly = next_poly;
  }
}

/**
 * Allocates an empty block
 */
struct RabinChunker::rabin_block_info *RabinChunker::init_empty_block() {
  struct rabin_block_info *block =
      (rabin_block_info *)malloc(sizeof(struct rabin_block_info));
  if (block == nullptr) {
    LOG(ERROR)
        << "Could not allocate rabin polynomial block, no memory left!\n";
    return nullptr;
  }

  // init with a dummy rabin fingerprint node
  block->head = gen_new_polynomial(nullptr, 0, 0, 0);
  // could not allocate memory
  if (block->head == nullptr)
    return nullptr;

  block->tail = block->head;
  block->cur_roll_checksum = 0;
  block->total_bytes_read = 0;
  block->window_pos = 0;
  block->cur_poly_finished = 0;
  block->cur_window_data =
      (char *)malloc(sizeof(char) * rabin_sliding_window_size_);

  if (block->cur_window_data == nullptr) {
    LOG(ERROR) << "Could not allocate buffer for sliding window data!\n";
    free(block);
    return nullptr;
  }
  for (int i = 0; i < (int)rabin_sliding_window_size_; i++) {
    block->cur_window_data[i] = 0;
  }

  return block;
}

/**
 * Read a block of memory and generates a rabin fingerprint list from it.
 * Since most of the time we will not end on a border, the function returns
 * a block struct, which keeps track of the current blocksum and rolling
 * checksum
 */
struct RabinChunker::rabin_block_info *
RabinChunker::read_rabin_block(const void *buf, size_t size,
                               struct rabin_block_info *cur_block) {
  struct rabin_block_info *block;
  if (cur_block == nullptr) {
    block = init_empty_block();
    if (block == nullptr) {
      return nullptr;
    }
  } else {
    block = cur_block;
  }

  // end on a border, generate a new tail.
  if (block->cur_poly_finished) {
    struct rabin_polynomial *new_poly = gen_new_polynomial(nullptr, 0, 0, 0);
    block->tail->next_polynomial = new_poly;
    block->tail = new_poly;
    block->cur_poly_finished = 0;
  }

  for (size_t i = 0; i < size; i++) {

    char cur_byte = *((char *)buf + i);
    char pushed_out = block->cur_window_data[block->window_pos];
    block->cur_window_data[block->window_pos] = cur_byte;
    block->cur_roll_checksum =
        (block->cur_roll_checksum * rabin_polynomial_prime_) + cur_byte;
    block->tail->polynomial =
        (block->tail->polynomial * rabin_polynomial_prime_) + cur_byte;
    block->cur_roll_checksum -=
        (pushed_out * polynomial_lookup_buf_[rabin_sliding_window_size_]);
    block->window_pos++;
    block->total_bytes_read++;
    block->tail->length++;

    // cur_window_data is a ring buffer
    // if reach the end of cur_window_data, then loop back around to the start
    // position
    if (block->window_pos == rabin_sliding_window_size_)
      block->window_pos = 0;

    // If we hit our special value and reach min block size
    // or reached the max block size
    // then create a new block.
    if ((block->tail->length >= rabin_polynomial_min_block_size_ &&
         (block->cur_roll_checksum % rabin_polynomial_average_block_size_) ==
             rabin_polynomial_prime_) ||
        block->tail->length == rabin_polynomial_max_block_size_) {
      block->tail->start = block->total_bytes_read - block->tail->length;
      // std::cout << "find one:"  << block->tail->length << std::endl;
      if (i == size - 1) {
        block->cur_poly_finished = 1;
        break;
      }
        
      struct rabin_polynomial *new_poly = gen_new_polynomial(block->tail, block->total_bytes_read, 0, 0);
      block->tail->next_polynomial = new_poly;
      block->tail = new_poly;
    }
  }
  return block;
}

std::vector<unsigned long int> RabinChunker::doChunk(const unsigned char *data,
                                                     unsigned int len) {
  auto block = read_rabin_block((const void *)data, len, nullptr);
  std::cout << "read block success" << std::endl;
  std::vector<unsigned long int> res;
  auto st = block->head;
  if(st == nullptr) {
    std::cout << "null" << std::endl;
    return {};
  }
  do {
    // std::cout << "chunk offset: " << st->start << ", chunk size: " << st->length << std::endl;
    res.push_back(st->start);
    st = st->next_polynomial;
  } while (st != nullptr);
  std::cout << "dochunk success, return to dedup" << std::endl;
  return res;
}

/*
void print_rabin_poly_list_to_file(FILE *out_file, struct rabin_polynomial
*poly) {

    struct rabin_polynomial *cur_poly=poly;

    while(cur_poly != nullptr) {
        print_rabin_poly_to_file(out_file,cur_poly,1);
        cur_poly=cur_poly->next_polynomial;
    }

}

void print_rabin_poly_to_file(FILE *out_file, struct rabin_polynomial *poly,int
new_line) {

    if(poly == nullptr)
        return;

    fprintf(out_file, "%llu,%u %llu",poly->start,poly->length,poly->polynomial);

    if(new_line)
        fprintf(out_file, "\n");
}

int write_rabin_fingerprints_to_binary_file(FILE *file,struct rabin_polynomial
*head) {

    struct rabin_polynomial *poly=head;

    while(poly != nullptr) {
        size_t ret_val=fwrite(poly, sizeof(struct rabin_polynomial), 1, file);

        if(ret_val == 0) {
            fprintf(stderr, "Could not write rabin polynomials to file.");
            return -1;
        }

        poly=poly->next_polynomial;
    }

    return 0;
}

struct rabin_polynomial *read_rabin_polys_from_file_binary(FILE *file) {
    struct rabin_polynomial *head=gen_new_polynomial(nullptr,0,0,0);
    struct rabin_polynomial *tail=head;

    if(head == nullptr)
        return nullptr;

    size_t polys_read=fread(head, sizeof(struct rabin_polynomial), 1, file);

    while(polys_read != 0 && tail != nullptr) {
        struct rabin_polynomial *cur_poly=gen_new_polynomial(tail,0,0,0);
        fread(cur_poly, sizeof(struct rabin_polynomial), 1, file);
        tail=cur_poly;
    }

    return head;
}

struct rabin_polynomial *get_file_rabin_polys(FILE *file_to_read) {

    initialize_rabin_polynomial_defaults();

    struct rab_block_info *block=nullptr;
    char *file_data=malloc(RAB_FILE_READ_BUF_SIZE);

    if(file_data == nullptr) {
        fprintf(stderr,"Could not allocate buffer for reading input file to
rabin polynomial.\n"); return nullptr;
    }

    ssize_t bytes_read=fread(file_data,1,RAB_FILE_READ_BUF_SIZE,file_to_read);

    while(bytes_read != 0) {
        block=read_rabin_block(file_data,bytes_read,block);
        bytes_read=fread(file_data,1,RAB_FILE_READ_BUF_SIZE,file_to_read);
    }

    free(file_data);
    struct rabin_polynomial *head=block->head;
    free(block);
    return head;
}
*/
