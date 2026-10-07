#include "aes_ctr.hpp"
#include <replaceable/ctr_tables.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <stdexcept>
#include <vector>

namespace
{
    std::uint8_t gf_mul(std::uint8_t a, std::uint8_t b)
    {
        std::uint8_t out = 0;
        for (int i = 0; i < 8; ++i)
        {
            if (b & 1U)
            {
                out ^= a;
            }
            const bool hi = (a & 0x80U) != 0;
            a = static_cast<std::uint8_t>((a << 1U) & 0xFFU);
            if (hi)
            {
                a ^= 0x1BU;
            }
            b = static_cast<std::uint8_t>(b >> 1U);
        }
        return out;
    }

    using State = std::array<std::array<std::uint8_t, 4>, 4>;

    State state_from_words_be(const std::array<std::uint32_t, 4> &words)
    {
        State st{};
        for (std::size_t c = 0; c < 4; ++c)
        {
            const std::uint32_t w = words[c];
            st[0][c] = static_cast<std::uint8_t>((w >> 24) & 0xFFU);
            st[1][c] = static_cast<std::uint8_t>((w >> 16) & 0xFFU);
            st[2][c] = static_cast<std::uint8_t>((w >> 8) & 0xFFU);
            st[3][c] = static_cast<std::uint8_t>(w & 0xFFU);
        }
        return st;
    }

    std::array<std::uint32_t, 4> words_from_state_be(const State &st)
    {
        std::array<std::uint32_t, 4> out{};
        for (std::size_t c = 0; c < 4; ++c)
        {
            out[c] = (static_cast<std::uint32_t>(st[0][c]) << 24) |
                     (static_cast<std::uint32_t>(st[1][c]) << 16) |
                     (static_cast<std::uint32_t>(st[2][c]) << 8) |
                     static_cast<std::uint32_t>(st[3][c]);
        }
        return out;
    }

    void shift_rows(State &st)
    {
        std::rotate(st[1].begin(), st[1].begin() + 1, st[1].end());
        std::rotate(st[2].begin(), st[2].begin() + 2, st[2].end());
        std::rotate(st[3].begin(), st[3].begin() + 3, st[3].end());
    }

    void sub_bytes(State &st, const std::array<std::uint8_t, 256> &sbox)
    {
        for (std::size_t r = 0; r < 4; ++r)
        {
            for (std::size_t c = 0; c < 4; ++c)
            {
                st[r][c] = sbox[st[r][c]];
            }
        }
    }

    void mix_columns(State &st)
    {
        for (std::size_t c = 0; c < 4; ++c)
        {
            const std::uint8_t a0 = st[0][c];
            const std::uint8_t a1 = st[1][c];
            const std::uint8_t a2 = st[2][c];
            const std::uint8_t a3 = st[3][c];
            st[0][c] = static_cast<std::uint8_t>(gf_mul(a0, 2) ^ gf_mul(a1, 3) ^ a2 ^ a3);
            st[1][c] = static_cast<std::uint8_t>(a0 ^ gf_mul(a1, 2) ^ gf_mul(a2, 3) ^ a3);
            st[2][c] = static_cast<std::uint8_t>(a0 ^ a1 ^ gf_mul(a2, 2) ^ gf_mul(a3, 3));
            st[3][c] = static_cast<std::uint8_t>(gf_mul(a0, 3) ^ a1 ^ a2 ^ gf_mul(a3, 2));
        }
    }

    void add_round_key(State &st, const std::uint32_t *rk_words)
    {
        for (std::size_t c = 0; c < 4; ++c)
        {
            const std::uint32_t w = rk_words[c];
            st[0][c] ^= static_cast<std::uint8_t>((w >> 24) & 0xFFU);
            st[1][c] ^= static_cast<std::uint8_t>((w >> 16) & 0xFFU);
            st[2][c] ^= static_cast<std::uint8_t>((w >> 8) & 0xFFU);
            st[3][c] ^= static_cast<std::uint8_t>(w & 0xFFU);
        }
    }

    std::array<std::uint8_t, 256> build_sbox()
    {
        std::array<std::uint8_t, 256> sbox{};

        for (std::size_t i = 0; i < 256; ++i)
        {
            std::uint8_t b0 = ctr_tables::kT1[4 * i + 0];
            std::uint8_t b1 = ctr_tables::kT0[4 * i + 1];
            std::uint8_t b2 = ctr_tables::kT3[4 * i + 2];
            std::uint8_t b3 = ctr_tables::kT2[4 * i + 3];

            if (ctr_tables::kTablesMasked)
            {
                b0 ^= 0x55U;
                b1 ^= 0x55U;
                b2 ^= 0x55U;
                b3 ^= 0x55U;
            }

            std::array<int, 256> counts{};
            counts[b0]++;
            counts[b1]++;
            counts[b2]++;
            counts[b3]++;

            int best_count = -1;
            std::uint8_t best = 0;
            for (int v = 0; v < 256; ++v)
            {
                if (counts[v] > best_count)
                {
                    best_count = counts[v];
                    best = static_cast<std::uint8_t>(v);
                }
            }
            sbox[i] = best;
        }

        return sbox;
    }

    const std::array<std::uint8_t, 256> &get_sbox()
    {
        static const std::array<std::uint8_t, 256> sbox = build_sbox();
        return sbox;
    }

    std::array<std::uint8_t, 16> aes_encrypt_block(const std::array<std::uint8_t, 16> &block)
    {
        constexpr std::uint32_t rounds = ctr_tables::kRounds;

        std::array<std::uint32_t, 4> in_words{};
        for (std::size_t i = 0; i < 4; ++i)
        {
            in_words[i] = crypt::read_u32_be(&block[i * 4]);
        }

        State st = state_from_words_be(in_words);
        const auto &sbox = get_sbox();
        const std::uint32_t *rk = ctr_tables::kRoundKeys.data();

        add_round_key(st, rk + 0);
        for (std::uint32_t r = 1; r < rounds; ++r)
        {
            sub_bytes(st, sbox);
            shift_rows(st);
            mix_columns(st);
            add_round_key(st, rk + (r * 4));
        }
        sub_bytes(st, sbox);
        shift_rows(st);
        add_round_key(st, rk + (rounds * 4));

        const auto out_words = words_from_state_be(st);
        std::array<std::uint8_t, 16> out{};
        for (std::size_t i = 0; i < 4; ++i)
        {
            const std::uint32_t w = out_words[i];
            out[i * 4 + 0] = static_cast<std::uint8_t>((w >> 24) & 0xFFU);
            out[i * 4 + 1] = static_cast<std::uint8_t>((w >> 16) & 0xFFU);
            out[i * 4 + 2] = static_cast<std::uint8_t>((w >> 8) & 0xFFU);
            out[i * 4 + 3] = static_cast<std::uint8_t>(w & 0xFFU);
        }
        return out;
    }

    void increment_counter_dwords_le(std::array<std::uint8_t, 16> &ctr)
    {
        for (std::size_t i = 0; i < 4; ++i)
        {
            const std::size_t off = i * 4;
            std::uint32_t v = crypt::read_u32_le(&ctr[off]);
            v = (v + 1U);
            ctr[off + 0] = static_cast<std::uint8_t>(v & 0xFFU);
            ctr[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xFFU);
            ctr[off + 2] = static_cast<std::uint8_t>((v >> 16) & 0xFFU);
            ctr[off + 3] = static_cast<std::uint8_t>((v >> 24) & 0xFFU);
            if (v != 0U)
            {
                return;
            }
        }
    }

} // namespace

std::vector<std::uint8_t> crypt::decrypt_ctr_payload(
    const std::vector<std::uint8_t> &data,
    const std::array<std::uint8_t, 16> &counter)
{
    std::vector<std::uint8_t> out = data;
    std::array<std::uint8_t, 16> ctr = counter;

    for (std::size_t off = 0; off < out.size(); off += 16)
    {
        const std::array<std::uint8_t, 16> ks = aes_encrypt_block(ctr);
        const std::size_t chunk = std::min<std::size_t>(16, out.size() - off);
        for (std::size_t i = 0; i < chunk; ++i)
        {
            out[off + i] ^= ks[i];
        }
        increment_counter_dwords_le(ctr);
    }
    return out;
}

std::vector<std::uint8_t> crypt::decrypt_blob_data(
    const std::vector<std::uint8_t> &enc,
    const config &cfg,
    std::size_t max_len)
{
    // malformed or other-format blobs: fail with an empty payload like a missing asset
    const std::size_t header_end = std::max({cfg.payload_offset_off + 4, cfg.counter_size_off + 4, cfg.counter_off + 16});
    if (enc.size() < header_end)
    {
        return {};
    }

    const std::uint32_t payload_off = read_u32_le(&enc[cfg.payload_offset_off]);
    if (payload_off > enc.size())
    {
        return {};
    }
    const std::uint32_t counter_size = read_u32_le(&enc[cfg.counter_size_off]);

    std::array<std::uint8_t, 16> counter{};
    std::copy_n(enc.begin() + static_cast<std::ptrdiff_t>(cfg.counter_off), 16, counter.begin());

    const std::size_t available = enc.size() - payload_off;
    const std::size_t use_len = (max_len == static_cast<std::size_t>(-1))
                                    ? available
                                    : std::min(max_len, available);

    std::vector<std::uint8_t> data(enc.begin() + static_cast<std::ptrdiff_t>(payload_off),
                                   enc.begin() + static_cast<std::ptrdiff_t>(payload_off + use_len));
    return decrypt_ctr_payload(data, counter);
}

std::uint32_t crypt::read_u32_le(const std::uint8_t *p)
{
    return static_cast<std::uint32_t>(p[0]) |
           (static_cast<std::uint32_t>(p[1]) << 8) |
           (static_cast<std::uint32_t>(p[2]) << 16) |
           (static_cast<std::uint32_t>(p[3]) << 24);
}

std::uint32_t crypt::read_u32_be(const std::uint8_t *p)
{
    return (static_cast<std::uint32_t>(p[0]) << 24) |
           (static_cast<std::uint32_t>(p[1]) << 16) |
           (static_cast<std::uint32_t>(p[2]) << 8) |
           static_cast<std::uint32_t>(p[3]);
}

std::uint32_t crypt::read_u32_le(const std::vector<std::uint8_t> &b, std::size_t off)
{
    return read_u32_le(b.data() + off);
}

std::uint32_t crypt::read_u32_be(const std::vector<std::uint8_t> &b, std::size_t off)
{
    return read_u32_be(b.data() + off);
}
