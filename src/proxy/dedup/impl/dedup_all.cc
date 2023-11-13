// SPDX-License-Identifier: Apache-2.0

#include <algorithm>
#include "dedup_all.hh"

std::string DedupAll::scan(const unsigned char *data, const BlockLocation &dataInObjectLocation, std::map<BlockLocation::InObjectLocation, std::pair<Fingerprint, bool> >& blocks) {   
    // mark whole data buffer as a unique block
    // blocks.clear();
    // blocks.insert(std::make_pair(dataInObjectLocation.getBlockRange(), std::make_pair(Fingerprint(), /* is duplicated */ false)));
    auto newBlock = dataInObjectLocation;
    auto len = dataInObjectLocation.getBlockLength();
    auto blocks_offset = chunker_ -> doChunk(data, len);

    auto id = (int)dataInObjectLocation.getObjectNamespaceId();
    // check fingerprints whether committed under this namespaceId
    auto hash1 = committed_fgs_[id];
    auto hash2 = scanned_fgs_[id];
    std::vector<Fingerprint> fps;
    std::vector<std::pair<Fingerprint, BlockLocation> > res;
    
    
    for(auto item : blocks_offset) {
        BlockLocation local = dataInObjectLocation;
        local.setBlockRange(blocks_offset[i], (i == blocks_offset.size() - 1) ? len - blocks_offset[i] : blocks_offset[i + 1] - blocks_offset[i]);

        Fingerprint fp;
        const std::string str(data, (i == blocks_offset.size() - 1) ? len - blocks_offset[i] : blocks_offset[i + 1] - blocks_offset[i]);
        fp.computeFingerprint(data, str.size());
        fps.push_back(fp);
        res.push_back(std::make_pair(fp, local));
        if(hash1.count(fp.get()) == 0 || hash1[fp.get()].size() == 0) {
            // this is a unique block
            if(hash2.count(fp.get()) == 0) {
                std::vector<BlockLocation> res;
                res.push_back(local);
                hash2[fp.get()] = res;
            } else {
                hash2[fp.get()].push_back(local);
            }        
            blocks.insert(std::make_pair(local.getBlockRange(), std::make_pair(fp ,false)));
        } else {
            hash2[fp.get()].push_back(local);
            blocks.insert(std::make_pair(local, std::make_pair(fp ,true)));
        }
    }

    // return sha256 of the whole data
    Fingerprint fp;
    fp.computeFingerprint(data, len);
    hash_namespace_[fp.get()] = id;
    hash_[fp.get()] = res;
    return fp.get();
}

void DedupAll::commit(std::string commitId) {
    if(commitId == "update") {
        return;
    }
    int id = hash_namespace_[commitId];
    auto arr = hash_[commitId];
    auto hash1 = committed_fgs_[id];
    auto hash2 = scanned_fgs_[id];
    int n = arr.size();

    for(int i = 0;i < n;i ++) {
        auto fg = arr[i].first;
        auto block = arr[i].second;

        if(hash1.count(fg) == 0) {
            std::vector<BlockLocation> tmp;
            tmp.push_back(block);
            hash1[fg] = tmp;
        } else {
            hash1[fg].push_back(block);
        }
        auto it = std::find(hash2[fg].begin(), hash2[fg].end(), block);
        if(it != hash2[fg].end()) {
            hash2[fg].erase(it);
        }
    }
    
    return;
}

void DedupAll::abort(std::string commitId) {
    int id = hash_namespace_[commitId];
    auto arr = hash_[commitId];
    auto hash = scanned_fgs_[id];
    int n = arr.size();

    for(int i = 0;i < n;i ++) {
        auto fg = arr[i].first;
        auto block = arr[i].second;

        auto it = std::find(hash[fg].begin(), hash[fg].end(), block);
        if(it != hash[fg].end()) {
            hash[fg].erase(it);
        }
    }

    return;
}

// according to src in file_ops
// update is combined with commit
// so here update can be committed
// do not need to return new commitId. 
std::string DedupAll::update(const std::vector<Fingerprint> &fingerprints, const std::vector<BlockLocation> &oldLocations, const std::vector<BlockLocation> &newLocations) {
    int n = fingerprints.size();
    if(0 == n) {
        return "update";
    }
    int id = (int)oldLocations[0].getObjectNamespaceId();
    auto hash1 = committed_fgs_[id];
    auto hash2 = scanned_fgs_[id];
    for(int i = 0;i < n;i ++) {
        auto fg = fingerprints[i];
        if(hash1.count(fg)) {
            auto it = std::find(hash1[fg].begin(), hash1[fg].end(), oldLocations[i]);
            if(it != hash1[fg].end()) {
                it -> setBlockRange(newLocations[i].getBlockOffset(), newLocations[i].getBlockLength());
                it -> setObjectID(newLocations[i].getObjectNamespaceId(), newLocations[i].getObjectName(), newLocations[i].getObjectVersion());
                continue;
            }
        } else if(hash2.count(fg)) {
            auto it = std::find(hash2[fg].begin(), hash2[fg].end(), oldLocations[i]);
            if(it != hash2[fg].end()) {
                it -> setBlockRange(newLocations[i].getBlockOffset(), newLocations[i].getBlockLength());
                it -> setObjectID(newLocations[i].getObjectNamespaceId(), newLocations[i].getObjectName(), newLocations[i].getObjectVersion());
                continue;
            }
        }

    }
    return "update";
}

std::vector<BlockLocation> DedupAll::query(const unsigned char namespaceId, const std::vector<Fingerprint> &fingerprints) {
    std::vector<BlockLocation> ret;
    int id = (int)namespaceId;
    auto hash = committed_fgs_[id];
    for(auto fg : fingerprints) {
        int size = hash[fg].size();
        if(0 == size) {
            continue;
        } else {
            ret.push_back(hash[fg].at(0));
        }
    }
    return ret;
}