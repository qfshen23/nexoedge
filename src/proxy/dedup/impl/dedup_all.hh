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

    DedupAll() {
        chunker_ = new RabinChunker;
    }
    ~DedupAll() {
        delete chunker_;
    }

    /**
     * refer to DeduplicationModule::scan()
     **/

    std::string scan(const unsigned char *data, const BlockLocation &dataInObjectLocation, std::map<BlockLocation::InObjectLocation, std::pair<Fingerprint, bool> >& blocks);

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
    std::string update(const std::vector<Fingerprint> &fingerprints, const std::vector<BlockLocation> &oldLocations, const std::vector<BlockLocation> &newLocations);

private:
    RabinChunker* chunker_;

    /*
    // hash from filename to all fingerprints in this file
    // deduplicated for all files in one namespaceId
    std::map<std::string, std::vector<Fingerprint> > hash_[1 << 8]; 
    // commitId to all fingerprints for committing
    std::map<std::string, std::vector<Fingerprint> > hash_commit_;
    std::map<std::string, std::vector<Fingerprint> > committing_hash_;
    std::map<std::string, BlockLocation> committing_BlockLoc_;
    std::map<std::string, unsigned char> committing_Id_;
    */

    // fingerprint to location, committed
    std::map<Fingerprint, std::vector<BlockLocation> > committed_fgs_[1 << 8];
    // fingerprint to location, scanned
    std::map<Fingerprint, std::vector<BlockLocation> > scanned_fgs_[1 << 8];

    std::map<std::string, unsigned char> hash_namespace_;
    std::map<std::string, std::vector<std::pair<Fingerprint, BlockLocation> > > hash_;
};

#endif
