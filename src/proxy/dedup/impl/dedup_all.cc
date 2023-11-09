// SPDX-License-Identifier: Apache-2.0

#include "dedup_all.hh"

std::string DedupAll::scan(const unsigned char *data, const BlockLocation &dataInObjectLocation, std::map<BlockLocation::InObjectLocation, std::pair<Fingerprint, bool> >& blocks) {
    // mark whole data buffer as a unique block
    blocks.clear();
    blocks.insert(std::make_pair(dataInObjectLocation.getBlockRange(), std::make_pair(Fingerprint(), /* is duplicated */ false)));

    // assign a dummy commit it
    return "0";
}

void DedupAll::commit(std::string commitId) {
    return;
}

void DedupAll::abort(std::string commitId) {
    return;
}

std::string DedupAll::update(const std::vector<Fingerprint> &fingerprints, const std::vector<BlockLocation> &oldLocations, const std::vector<BlockLocation> &newLocations) {
    return "0";
}

std::vector<BlockLocation> DedupAll::query(const unsigned char namespaceId, const std::vector<Fingerprint> &fingerprints) {
    // report no such block, as no query on duplicated blocks are expected
    std::vector<BlockLocation> ret;
    ret.resize(fingerprints.size());
    return ret;
}