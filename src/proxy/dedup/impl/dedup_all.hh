// SPDX-License-Identifier: Apache-2.0

#ifndef __DEDUP_ALL_HH__
#define __DEDUP_ALL_HH__

#include <unordered_map>
#include "../chunking/rabin_chunker.hh"
#include "../dedup.hh"

class DedupAll : public DeduplicationModule {
 public:
  /**
   * Deduplication module that does data deduplication
   **/
  DedupAll() { chunker_ = new RabinChunker; }
  ~DedupAll() { delete chunker_; }
  /**
   * refer to DeduplicationModule::scan()
   **/
  std::string scan(const unsigned char *data, const BlockLocation &dataInObjectLocation,
                   std::map<BlockLocation::InObjectLocation, std::pair<Fingerprint, bool> > &blocks);

  /**
   * refer to DeduplicationModule::commit()
   **/
  void commit(std::string commitId);

  /**
   * refer to DeduplicationModule::abort()
   **/
  void abort(std::string commitId);

  /**
   * refer to DeduplicationModule::query()
   **/
  std::vector<BlockLocation> query(const unsigned char namespaceId, const std::vector<Fingerprint> &fingerprints);

  /**
   * refer to DeduplicationModule::update()
   **/
  std::string update(const std::vector<Fingerprint> &fingerprints, const std::vector<BlockLocation> &oldLocations,
                     const std::vector<BlockLocation> &newLocations);

 private:
  RabinChunker *chunker_;
  // fingerprint to location, scanned
  std::map<Fingerprint, std::vector<BlockLocation> > scanned_fgs_[1 << 8];
  // fingerprint to location, committed
  std::map<Fingerprint, std::vector<BlockLocation> > committed_fgs_[1 << 8];
  // commitId(str) to namespace id
  std::map<std::string, unsigned char> hash_namespace_;
  // commitId(str) to this batch's all updates
  std::map<std::string, std::vector<std::pair<Fingerprint, BlockLocation> > > hash_;
};

#endif
