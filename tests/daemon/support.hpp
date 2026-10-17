//
// Helpers for the forti-piholed tests: a temporary directory (never the user's forti home) and a
// fixed token.
//

#ifndef FORTI_PIHOLED_TESTS_SUPPORT_HPP
#define FORTI_PIHOLED_TESTS_SUPPORT_HPP

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <stdlib.h>

namespace fph::daemon::test {

    namespace fs = std::filesystem;

    inline constexpr const char* token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    class TempDir {
        fs::path path_;

    public:
        TempDir() {
            std::string pattern = (fs::temp_directory_path() / "forti-piholed-test-XXXXXX").string();
            if (!::mkdtemp(pattern.data())) throw std::runtime_error("mkdtemp failed");
            path_ = pattern;
        }
        ~TempDir() {
            std::error_code ignored;
            fs::remove_all(path_, ignored);
        }
        TempDir(const TempDir&) = delete;
        TempDir& operator=(const TempDir&) = delete;
        [[nodiscard]] const fs::path& path() const { return path_; }
    };

    inline std::string read_file(const fs::path& path) {
        std::ifstream in(path);
        std::stringstream buffer;
        buffer << in.rdbuf();
        return buffer.str();
    }

    inline void write_file(const fs::path& path, const std::string& text) {
        fs::create_directories(path.parent_path());
        std::ofstream(path) << text;
    }

}  // namespace fph::daemon::test

#endif  // FORTI_PIHOLED_TESTS_SUPPORT_HPP
