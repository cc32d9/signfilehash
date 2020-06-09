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

CONTRACT signfilehash : public eosio::contract {
 public:
  signfilehash( name self, name code, datastream<const char*> ds ):
    contract(self, code, ds)
    {}

  const uint64_t EXPIRES_SECONDS = 10; //TODO: set to 1 year
  
  const int MAX_ENDORSEMENTS = 10;

  ACTION addfile(name author, checksum256 hash, string filename, string description)
  {
    require_auth(author);
    files _files(_self, 0);

    check(filename.length() > 0, "Filename cannot be empty");
    
    auto hashidx = _files.get_index<name("hash")>();
    check(hashidx.find(hash) == hashidx.end(), "This hash is already registered");

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
                     f.description = description;
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

    auto hashidx = _files.get_index<name("hash")>();
    auto hashitr = hashidx.find(hash);
    check(hashidx.find(hash) != hashidx.end(), "Cannot find this file hash");
    check(hashitr->author != signor, "Author of the file does not need to endorse it");

    auto endidx = _endorsements.get_index<name("fileid")>();
    auto enditr = endidx.lower_bound(hashitr->id);
    int count = 0;
    while( enditr != endidx.end() && enditr->file_id == hashitr->id ) {
      check(enditr->signed_by != signor, "This signor has already endorsed this hash");
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
    check(done_something, "There are no expired entries");
  }
  

  
 private:

  struct [[eosio::table("files")]] file {
    uint64_t         id;             /* autoincrement */
    name             author;
    string           filename;
    string           description;
    checksum256      hash;
    checksum256      trxid;
    time_point_sec   expires;    

    auto primary_key()const { return id; }
    checksum256 get_hash() const { return hash; }
    uint64_t get_expires()const { return expires.utc_seconds; }
  };
  
  typedef eosio::multi_index<
    name("files"), file,
    indexed_by<name("hash"), const_mem_fun<file, checksum256, &file::get_hash>>,
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

  
