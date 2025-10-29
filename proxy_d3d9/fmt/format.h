#pragma once

#include <sstream>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

namespace fmt {

class memory_buffer {
public:
    memory_buffer() = default;

    void push_back(char c) { buffer_.push_back(c); }
    void append(std::string_view sv) { buffer_.append(sv.data(), sv.size()); }

    std::string::size_type size() const { return buffer_.size(); }
    const char* data() const { return buffer_.data(); }

    std::string str() const { return buffer_; }

private:
    std::string buffer_;

    friend std::string to_string(const memory_buffer& buf);
};

inline std::string to_string(const memory_buffer& buf) {
    return buf.buffer_;
}

namespace detail {

inline void AppendArg(memory_buffer& buf, std::string_view sv) {
    buf.append(sv);
}

inline void AppendArg(memory_buffer& buf, const char* s) {
    buf.append(s ? std::string_view{s} : std::string_view{"(null)"});
}

inline void AppendArg(memory_buffer& buf, char* s) {
    AppendArg(buf, static_cast<const char*>(s));
}

inline void AppendArg(memory_buffer& buf, char c) {
    buf.push_back(c);
}

inline void AppendArg(memory_buffer& buf, const std::string& s) {
    buf.append(s);
}

inline void AppendArg(memory_buffer& buf, std::string&& s) {
    buf.append(s);
}

template <typename T>
inline auto ToString(const T& value) -> std::string {
    if constexpr (std::is_same_v<T, std::string>) {
        return value;
    }
    else if constexpr (std::is_same_v<T, std::string_view>) {
        return std::string(value);
    }
    else {
        std::ostringstream oss;
        oss << value;
        return oss.str();
    }
}

template <typename T>
inline void AppendArg(memory_buffer& buf, const T& value) {
    buf.append(ToString(value));
}

template <typename T>
inline void ProcessArg(memory_buffer& buf, T&& value) {
    AppendArg(buf, std::forward<T>(value));
}

inline void ProcessFormat(memory_buffer& buf, std::string_view fmt) {
    buf.append(fmt);
}

template <typename Arg, typename... Args>
inline void ProcessFormat(memory_buffer& buf, std::string_view fmt, Arg&& arg, Args&&... rest) {
    std::string result;
    result.reserve(fmt.size());
    std::size_t i = 0;
    while (i < fmt.size()) {
        char ch = fmt[i];
        if (ch == '{') {
            if (i + 1 < fmt.size() && fmt[i + 1] == '{') {
                result.push_back('{');
                i += 2;
                continue;
            }
            if (i + 1 < fmt.size() && fmt[i + 1] == '}') {
                // emit accumulated prefix
                if (!result.empty()) {
                    buf.append(result);
                    result.clear();
                }
                detail::ProcessArg(buf, std::forward<Arg>(arg));
                fmt.remove_prefix(i + 2);
                ProcessFormat(buf, fmt, std::forward<Args>(rest)...);
                return;
            }
        }
        if (ch == '}' && i + 1 < fmt.size() && fmt[i + 1] == '}') {
            result.push_back('}');
            i += 2;
            continue;
        }
        result.push_back(ch);
        ++i;
    }
    buf.append(result);
}

} // namespace detail

template <typename... Args>
inline void format_to(memory_buffer& buf, std::string_view fmt, Args&&... args) {
    detail::ProcessFormat(buf, fmt, std::forward<Args>(args)...);
}

template <typename... Args>
inline std::string format(std::string_view fmt, Args&&... args) {
    memory_buffer buf;
    format_to(buf, fmt, std::forward<Args>(args)...);
    return to_string(buf);
}

} // namespace fmt

