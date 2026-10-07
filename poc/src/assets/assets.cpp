#include <appdome.hpp>
#include <logcat.hpp>
#include <crypt/aes_ctr.hpp>
#include <replaceable/blobs_magic.h>
#include "SHA256.h"

#include <fstream>

static std::unordered_map< std::string, std::string > HASH_KEYS;

namespace
{
    std::string clean_text(const std::vector<std::uint8_t> &b, std::size_t off, std::size_t len)
    {
        std::string s;
        s.reserve(len);
        for (std::size_t i = 0; i < len; ++i)
        {
            const unsigned char c = b[off + i];
            if (c == 0)
            {
                break;
            }
            s.push_back(static_cast<char>(c));
        }
        return s;
    }

    bool is_upper_hex(unsigned char c)
    {
        return (c >= '0' && c <= '9') || (c >= 'A' && c <= 'F');
    }

    bool looks_like_upperhex64(const std::vector<std::uint8_t> &blob, std::size_t off)
    {
        if (off + 64 > blob.size())
        {
            return false;
        }
        for (std::size_t i = 0; i < 64; ++i)
        {
            if (!is_upper_hex(blob[off + i]))
            {
                return false;
            }
        }
        return true;
    }

    std::string read_string(const std::vector<std::uint8_t> &blob, std::size_t off, std::size_t len)
    {
        return std::string(blob.begin() + static_cast<std::ptrdiff_t>(off),
                           blob.begin() + static_cast<std::ptrdiff_t>(off + len));
    }

    std::unordered_map<std::string, std::string> parse_hash_map(const std::vector<std::uint8_t> &blob)
    {
        std::unordered_map<std::string, std::string> out;
        const std::size_t n = blob.size();

        std::size_t i = 0;
        while (i + 70 <= n)
        {
            if (blob[i] != 0xF6)
            {
                ++i;
                continue;
            }

            const std::size_t key_off = i + 1;
            if (!looks_like_upperhex64(blob, key_off))
            {
                ++i;
                continue;
            }

            const std::size_t key_term_off = i + 65;
            if (blob[key_term_off] != 0x00)
            {
                ++i;
                continue;
            }

            const std::size_t len_off = i + 66;
            const std::uint32_t value_len_u32 = crypt::read_u32_le(blob, len_off);
            const std::size_t value_len = static_cast<std::size_t>(value_len_u32);

            const std::size_t value_off = i + 70;
            const std::size_t value_end = value_off + value_len;
            if (value_end < value_off || value_end > n)
            {
                ++i;
                continue;
            }

            const std::string key = read_string(blob, key_off, 64);
            const std::string value(blob.begin() + static_cast<std::ptrdiff_t>(value_off),
                                    blob.begin() + static_cast<std::ptrdiff_t>(value_end));
            out[key] = value;

            i = value_end;
        }

        return out;
    }

    std::string resolve_uuid_from_name(const std::string &name)
    {
        std::string identifier = name + BLOBS_MAGIC;
        std::string hash_key = sha256(identifier);
        log_D("sha256 for %s : %s", identifier.c_str(), hash_key.c_str());

        std::transform(hash_key.begin(), hash_key.end(), hash_key.begin(), ::toupper);
        log_D("upper: %s", hash_key.c_str());

        auto it = HASH_KEYS.find(hash_key);
        if (it == HASH_KEYS.end())
        {
            log_E("couldnt find an uuid for this blob: %s", name.c_str());
            return std::string();
        }

        return it->second;
    }
}

std::string assets::get_by_uuid(const std::string &uuid)
{
    std::string blob_path = ASSETS_PACKAGES_DIR + uuid;
    std::string encrypted_blob_data = get_apk_asset(blob_path);
    if (encrypted_blob_data.empty())
    {
        log_E("Failed to load blob with UUID: %s", uuid.c_str());
        return std::string();
    }

    auto decrypted_blob = crypt::decrypt_blob_data(std::vector<unsigned char>(encrypted_blob_data.begin(), encrypted_blob_data.end()));
    std::string decrypted_blob_str(decrypted_blob.begin(), decrypted_blob.end());
    return decrypted_blob_str;
}

std::string assets::get_from_name(const std::string &name)
{
    std::string uuid = resolve_uuid_from_name(name);
    if (uuid.empty()) {
        return std::string( );
    }
    return get_by_uuid( uuid );
}

std::string assets::get_as_key(const std::string &name)
{
    return resolve_uuid_from_name(name);
}

void assets::populate_hash_map(const std::string &blobs_config)
{
    auto parsed_config = parse_hash_map( std::vector<std::uint8_t>(blobs_config.begin(), blobs_config.end()) );
    HASH_KEYS = std::move(parsed_config);

    log_D("parsed blobs config: %zu pairs", HASH_KEYS.size());
    log_D("hash keys in config:");
    for (const auto& pair : HASH_KEYS) {
        log_D("  %s -> %s", pair.first.c_str(), pair.second.c_str());
    }
}
