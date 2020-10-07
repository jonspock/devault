// Copyright (c) 2017 The Bitcoin Core developers
// Copyright (c) 2019 The Devault developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// clang-format off
#pragma once

#include <cstdio>
#include <string>

#ifdef NO_BOOST_FILESYSTEM
#include <filesystem>
#else
#include <boost/filesystem.hpp>
#include <boost/filesystem/path.hpp>
#endif

#ifdef NO_BOOST_FILESYSTEM
namespace fs = std::filesystem;
#else
/** Filesystem operations and types */
namespace fs = boost::filesystem;
#endif

/** Bridge operations to C stdio */
namespace fsbridge {
inline FILE *fopen(const fs::path &p, const char *mode) {   return ::fopen(p.string().c_str(), mode);}

FILE *freopen(const fs::path &p, const char *mode, FILE *stream);

class FileLock {
public:
    FileLock() = delete;
    FileLock(const FileLock &) = delete;
    FileLock(FileLock &&) = delete;
    explicit FileLock(const fs::path &file);
    ~FileLock();
    bool TryLock();
    std::string GetReason() { return reason; }

private:
    std::string reason;
#ifndef WIN32
    int fd = -1;
#else
    // INVALID_HANDLE_VALUE
    void *hFile = (void *)-1;
#endif
};
  
}; // namespace fsbridge

// clang-format on
