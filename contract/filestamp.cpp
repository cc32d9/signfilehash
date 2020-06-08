/*
Copyright 2020 cc32d9@gmail.com

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <eosio/eosio.hpp>
#include <eosio/multi_index.hpp>
#include <eosio/string.hpp>
#include <eosio/crypto.hpp>
#include <eosio/system.hpp>
#include <eosio/transaction.hpp>


using namespace eosio;
using std::vector;

CONTRACT filestamp : public eosio::contract {
 public:
  filestamp( name self, name code, datastream<const char*> ds ):
    contract(self, code, ds)
    {}

  const uint64_t EXPIRES_SECONDS = 10; //TODO: set to 1 year
  
  const int MAX_ENDORSEMENTS = 10;

  ACTION addfile(name author, string filename, checksum256 hash)
  {
    require_auth(author);
    files _files(_self, 0);

    // hash64 is considered non-unique, although highly unlikely to have collisions)
    uint64_t h64 = hash64(hash);
    auto hashidx = _files.get_index<name("hash")>();
    auto hashitr = hashidx.lower_bound(h64);
    while( hashitr != hashidx.end() && hash64(hashitr->hash) == h64 ) {
      check(hashitr->hash != hash, "This hash is already registered");
      hashitr++;
    }

    auto trxsize = transaction_size();
    char trxbuf[trxsize];
    uint32_t trxread = read_transaction( trxbuf, trxsize );
    check( trxsize == trxread, "read_transaction failed");
    checksum256 trxid = sha256(trxbuf, trxsize);

    _files.emplace(author,
                   [&]( auto& f ) {
                     f.id = _files.available_primary_key();
                     f.author = author;
                     f.filename = filename;
                     f.hash = hash;
                     f.trxid = trxid;
                     f.expires = time_point_sec(current_time_point()) + EXPIRES_SECONDS;
                   });
  }



  ACTION endorse(name signor, checksum256 hash)
  {
    require_auth(signor);
    files _files(_self, 0);
    endorsements _endorsements(_self, 0);

    uint64_t h64 = hash64(hash);
    auto hashidx = _files.get_index<name("hash")>();
    auto hashitr = hashidx.lower_bound(h64);
    while( hashitr != hashidx.end() && hash64(hashitr->hash) == h64 ) {
      if(hashitr->hash == hash) {
        check(hashitr->author != signor, "Author of the file does not need to endorse it");
        auto endidx = _endorsements.get_index<name("fileid")>();
        auto enditr = endidx.lower_bound(hashitr->id);
        int count = 0;
        while( enditr != endidx.end() && enditr->file_id == hashitr->id ) {
          check(enditr->signed_by != signor, "This sognor has already endorsed this hash");
          check(++count < MAX_ENDORSEMENTS, "Too many endorsements for this hash");
          enditr++;
        }

        auto trxsize = transaction_size();
        char trxbuf[trxsize];
        uint32_t trxread = read_transaction( trxbuf, trxsize );
        check( trxsize == trxread, "read_transaction failed");
        checksum256 trxid = sha256(trxbuf, trxsize);
        
        _endorsements.emplace(signor,
                              [&]( auto& e ) {
                                e.id = _endorsements.available_primary_key();
                                e.file_id = hashitr->id;
                                e.signed_by = signor;
                                e.trxid = trxid;
                              });
        return;
      }
      
      hashitr++;
    }
    check(false, "Cannot find this file hash");
  }

  
  // erase up to X expired file hashes
  ACTION wipeexpired(uint16_t count)
  {
    bool done_something = false;
    auto _now = time_point_sec(current_time_point());
    files _files(_self, 0);
    endorsements _endorsements(_self, 0);
    auto fileidx = _files.get_index<name("expires")>();
    auto fileitr = fileidx.begin(); // it starts with earliest files
    auto endidx = _endorsements.get_index<name("fileid")>();

    while( count-- > 0 && fileitr != fileidx.end() && fileitr->expires <= _now ) {
      auto enditr = endidx.lower_bound(fileitr->id);
      while( enditr != endidx.end() && enditr->file_id == fileitr->id ) {
        enditr = endidx.erase(enditr);
      }
      fileitr = fileidx.erase(fileitr);
      done_something = true;
    }
    check(done_something, "There are no expired transactions or inactive arbiters");
  }
  

  
 private:

  static uint64_t hash64(const checksum256 h) {
    auto hbytes = h.extract_as_byte_array();
    uint64_t ret = 0;
    for(int i=0; i<8; ++i) {
      ret <<=8;
      ret |= hbytes[i];
    }
    return ret;
  }

  struct [[eosio::table("files")]] file {
    uint64_t         id;             /* autoincrement */
    name             author;
    string           filename;
    checksum256      hash;
    checksum256      trxid;
    time_point_sec   expires;    

    auto primary_key()const { return id; }
    uint64_t get_hash64() const { return hash64(hash); }
    uint64_t get_expires()const { return expires.utc_seconds; }
  };
  
  typedef eosio::multi_index<
    name("files"), file,
    indexed_by<name("hash"), const_mem_fun<file, uint64_t, &file::get_hash64>>,
    indexed_by<name("expires"), const_mem_fun<file, uint64_t, &file::get_expires>>
    > files;

  struct [[eosio::table("endorsements")]] endorsement {
    uint64_t         id;             /* autoincrement */
    uint64_t         file_id;
    name             signed_by;
    checksum256      trxid;

    auto primary_key()const { return id; }
    uint64_t get_fileid() const { return file_id; }
  };
    
  typedef eosio::multi_index<name("endorsements"), endorsement,
    indexed_by<name("fileid"), const_mem_fun<endorsement, uint64_t, &endorsement::get_fileid>>> endorsements;
  
};

  
