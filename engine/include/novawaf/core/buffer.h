// NovaWAF - 零拷贝 Buffer (read/write 游标，避免频繁内存分配)
#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
using ssize_t = std::intptr_t;
#endif

namespace novawaf {

class Buffer {
public:
    static constexpr size_t kInitialSize = 4096;

    Buffer() : buffer_(kInitialSize), reader_idx_(0), writer_idx_(0) {}

    size_t readableBytes() const { return writer_idx_ - reader_idx_; }
    size_t writableBytes() const { return buffer_.size() - writer_idx_; }
    size_t prependableBytes() const { return reader_idx_; }

    const char* peek() const { return begin() + reader_idx_; }

    std::string_view toStringView() const {
        return std::string_view(peek(), readableBytes());
    }

    void retrieve(size_t len) {
        if (len < readableBytes())
            reader_idx_ += len;
        else
            retrieveAll();
    }

    void retrieveAll() { reader_idx_ = writer_idx_ = 0; }

    std::string retrieveAsString(size_t len) {
        std::string result(peek(), len);
        retrieve(len);
        return result;
    }

    void append(const char* data, size_t len) {
        ensureWritable(len);
        std::memcpy(beginWrite(), data, len);
        hasWritten(len);
    }

    void append(std::string_view sv) { append(sv.data(), sv.size()); }

    char* beginWrite() { return begin() + writer_idx_; }
    const char* beginWrite() const { return begin() + writer_idx_; }

    void hasWritten(size_t len) { writer_idx_ += len; }

    void ensureWritable(size_t len) {
        if (writableBytes() < len) makeSpace(len);
    }

    // 从 fd 读取 (Linux 用 readv，Windows 退化为 recv)
    ssize_t readFd(int fd, int* savedErrno);

private:
    char* begin() { return buffer_.data(); }
    const char* begin() const { return buffer_.data(); }

    void makeSpace(size_t len) {
        if (writableBytes() + prependableBytes() < len) {
            buffer_.resize(writer_idx_ + len);
        } else {
            size_t readable = readableBytes();
            std::memmove(begin(), begin() + reader_idx_, readable);
            reader_idx_ = 0;
            writer_idx_ = readable;
        }
    }

    std::vector<char> buffer_;
    size_t reader_idx_;
    size_t writer_idx_;
};

}  // namespace novawaf
