// SPDX-License-Identifier: Apache-2.0

#include "rabin_fingerprint.hh"
#include "rabin_constrants.hh"


RabinFingerPrint::RabinFingerPrint(): 
        rabin_polynomial_prime_(RABIN_POLYNOMIAL_REM), 
        rabin_sliding_window_size_(RABIN_POLYNOMIAL_WIN_SIZE), 
        rabin_polynomial_average_block_size_(RABIN_POLYNOMIAL_AVG_BLOCK_SIZE),
        rabin_polynomial_max_block_size_(RABIN_MAX_BLOCK_SIZE),
        rabin_polynomial_min_block_size_(RABIN_MIN_BLOCK_SIZE) 
{
    rabin_info_ = (rabin_block_info*)new(sizeof(rabin_block_info));
    if(rabin_info_ == nullptr) {
        LOG(ERROR) << "Could not initialize rabin polynomial info, out of memory!\n";
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

    polynomial_lookup_buf_ = new(sizeof(uint64_t) * RABIN_POLYNOMIAL_MAX_WIN_SIZE);
    
    if(polynomial_lookup_buf_ == nullptr) {
        LOG(ERROR) << "Could not initialize rabin polynomial lookaside buffer, out of memory!\n";
        return;
    }
    
    int index = 0;
    uint64_t curPower = 1;
    // Initialize the lookup values we will need later
    for(index = 0;index < RABIN_POLYNOMIAL_MAX_WIN_SIZE;index ++) {
        // TODO check if max window size is a power of 2
        // and if so use shifters instead of multiplication
        polynomial_lookup_buf_[index] = curPower;
        curPower *= rabin_polynomial_prime_;
    }
}

RabinFingerPrint::~RabinFingerPrint() {
    delete [] polynomial_lookup_buf_;
    // ****** may be need to delete the linked-list here
    // (free_rabin_fingerprint_list)
    delete rabin_info_;
}

/**
 * Modifies the average block size, checking to make sure it doesn't
 * go above the max or below the min
 */
void change_average_rabin_block_size(int increment_mode) {
    if(increment_mode != 0 and rabin_polynomial_average_block_size_ < rabin_polynomial_max_block_size_) {
        rabin_polynomial_average_block_size_ ++;
    } else if(increment_mode == 0 and rabin_polynomial_average_block_size_ > rabin_polynomial_min_block_size_) {
        rabin_polynomial_average_block_size --;
    }
}

/*
 * Generate a new fingerprint with the given info and add it to the tail
 */
struct rabin_polynomial *gen_new_polynomial(struct rabin_polynomial *tail, uint64_t total_len, uint16_t length, uint64_t rab_sum) {
    struct rabin_polynomial *next = malloc(sizeof(struct rabin_polynomial));
    
    if(next == nullptr) {
        LOG(ERROR) << "Could not allocate memory for rabin fingerprint record!\n";
        return NULL;
    }
    
    if(tail != nullptr) {
        tail->next_polynomial = next;
    }
        
    next -> next_polynomial = nullptr;
    next -> start = total_len - length;
    next -> length = length;
    next -> polynomial = rab_sum;
    
    return next;
}

/*
 * Deallocates the entire fingerprint list
 */
void free_rabin_fingerprint_list(struct rabin_polynomial *head) {
    
    struct rabin_polynomial *cur_poly,*next_poly;
    
    cur_poly=head;
    
    while(cur_poly != NULL) {
        next_poly=cur_poly->next_polynomial;
        free(cur_poly);
        cur_poly=next_poly;
    }
    
}

/**
 * Allocates an empty block
 */
struct rab_block_info *init_empty_block() {
	struct rab_block_info *block = malloc(sizeof(struct rab_block_info));
    if(block == nullptr) {
        LOG(ERROR) << "Could not allocate rabin polynomial block, no memory left!\n";
        return NULL;
    }
	
	block->head=gen_new_polynomial(NULL,0,0,0);
    
	if(block->head == NULL)
        return NULL; //Couldn't allocate memory
    
	block->tail=block->head;
	block->cur_roll_checksum=0;
	block->total_bytes_read=0;
	block->window_pos=0;
	block->current_poly_finished=0;
    
    block->current_window_data=malloc(sizeof(char)*rabin_sliding_window_size);
    
	if(block->current_window_data == NULL) {
	    fprintf(stderr,"Could not allocate buffer for sliding window data!\n");
	    free(block);
	    return NULL;
	}
    int i;
	for(i=0;i<rabin_sliding_window_size;i++) {
	    block->current_window_data[i]=0;
	}
    
    return block;
}

/**
 * Reads a block of memory and generates a rabin fingerprint list from it.
 * Since most of the time we will not end on a border, the function returns
 * a block struct, which keeps track of the current blocksum and rolling checksum
 */
struct rab_block_info *read_rabin_block(void *buf, ssize_t size, struct rab_block_info *cur_block) {
    struct rab_block_info *block;
    
    if(cur_block == NULL) {
        block=init_empty_block();
        if(block == NULL)
            return NULL;
    }
    
    else {
     	block=cur_block;
    }
    //We ended on a border, gen a new tail
    if(block->current_poly_finished) {
        struct rabin_polynomial *new_poly=gen_new_polynomial(NULL,0,0,0);
        block->tail->next_polynomial=new_poly;
        block->tail=new_poly;
        block->current_poly_finished=0;
    }
   

    ssize_t i;
    for(i=0;i<size;i++) {
    	char cur_byte=*((char *)(buf+i));
        char pushed_out=block->current_window_data[block->window_pos];
        block->current_window_data[block->window_pos]=cur_byte;
        block->cur_roll_checksum=(block->cur_roll_checksum*rabin_polynomial_prime)+cur_byte;
        block->tail->polynomial=(block->tail->polynomial*rabin_polynomial_prime)+cur_byte;
        block->cur_roll_checksum-=(pushed_out*polynomial_lookup_buf[rabin_sliding_window_size]);
        
        block->window_pos++;
        block->total_bytes_read++;
        block->tail->length++;
        
        if(block->window_pos == rabin_sliding_window_size) //Loop back around
            block->window_pos=0;
        
        //If we hit our special value or reached the max win size create a new block
        if((block->tail->length >= rabin_polynomial_min_block_size && (block->cur_roll_checksum % rabin_polynomial_average_block_size) == rabin_polynomial_prime)|| block->tail->length == rabin_polynomial_max_block_size) {
            block->tail->start=block->total_bytes_read-block->tail->length;
            struct rabin_polynomial *new_poly=gen_new_polynomial(NULL,0,0,0);
            block->tail->next_polynomial=new_poly;
            block->tail=new_poly;
            
            if(i==size-1)
                block->current_poly_finished=1;
        }
    }
    
    return block;
    
}







/**
 * Prints the list of rabin polynomials to the given file
 */
void print_rabin_poly_list_to_file(FILE *out_file, struct rabin_polynomial *poly) {
    
    struct rabin_polynomial *cur_poly=poly;
    
    while(cur_poly != NULL) {
        print_rabin_poly_to_file(out_file,cur_poly,1);
        cur_poly=cur_poly->next_polynomial;
    }
    
}

/**
 * Prints a given rabin polynomial to file in the format:
 * start,length hash
 */
void print_rabin_poly_to_file(FILE *out_file, struct rabin_polynomial *poly,int new_line) {
    
    if(poly == NULL)
        return;
    
    fprintf(out_file, "%llu,%u %llu",poly->start,poly->length,poly->polynomial);
    
    if(new_line)
        fprintf(out_file, "\n");
}

/*
 * Writes out the fingerprint list in binary form
 */
int write_rabin_fingerprints_to_binary_file(FILE *file,struct rabin_polynomial *head) {
    
    struct rabin_polynomial *poly=head;
    
    while(poly != NULL) {
        size_t ret_val=fwrite(poly, sizeof(struct rabin_polynomial), 1, file);
        
        if(ret_val == 0) {
            fprintf(stderr, "Could not write rabin polynomials to file.");
            return -1;
        }
        
        poly=poly->next_polynomial;
    }
    
    return 0;
}

/**
 * Reads a list of rabin fingerprints in binary form
 */
struct rabin_polynomial *read_rabin_polys_from_file_binary(FILE *file) {
    struct rabin_polynomial *head=gen_new_polynomial(NULL,0,0,0);
    struct rabin_polynomial *tail=head;
    
    if(head == NULL)
        return NULL;
    
    size_t polys_read=fread(head, sizeof(struct rabin_polynomial), 1, file);
    
    while(polys_read != 0 && tail != NULL) {
        struct rabin_polynomial *cur_poly=gen_new_polynomial(tail,0,0,0);
        fread(cur_poly, sizeof(struct rabin_polynomial), 1, file);
        tail=cur_poly;
    }
    
    return head;
}




/*
 * Gets the list of fingerprints from the given file
 */

struct rabin_polynomial *get_file_rabin_polys(FILE *file_to_read) {
    
    initialize_rabin_polynomial_defaults();
    
    struct rab_block_info *block=NULL;
    char *file_data=malloc(RAB_FILE_READ_BUF_SIZE);
    
    if(file_data == NULL) {
        fprintf(stderr,"Could not allocate buffer for reading input file to rabin polynomial.\n");
        return NULL;
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

