#ifndef LOGGING_H
#define LOGGING_H

#include <iostream>
#include <string>
#include <sstream>
#include <vector>

/**
 * @brief Simple, configurable logging utility.
 *
 * The Logger provides a global, lightweight mechanism for emitting
 * diagnostic messages. Logging can be enabled or disabled globally
 * and redirected to any std::ostream.
 */
class Logger {
public:
    /**
     * @brief Global flag that controls whether logging is enabled.
     */
    static bool enable_logging;

    /**
     * @brief Output stream used for log messages.
     *
     * Defaults to std::cout, but can be overridden via setOutputStream().
     */
    static std::ostream* out;

    /**
     * @brief Write a message to the log if logging is enabled.
     *
     * @param message Message to log.
     */
    static void log(const std::string& message) {
        if (enable_logging && out) {
            *out << message << std::endl;
        }
    }

    /**
     * @brief Convert a vector to a formatted string.
     *
     * @tparam T Element type.
     * @param vec Vector to convert.
     * @param prefix Optional prefix to prepend to the formatted output.
     * @return String of the form "prefix[elem0, elem1, ...]".
     */
    template<typename T>
    static std::string vectorToString(const std::vector<T>& vec, const std::string& prefix = "") {
        std::stringstream ss;
        ss << prefix << "[";
        for (size_t i = 0; i < vec.size(); ++i) {
            if (i > 0) {
                ss << ", ";
            }
            ss << vec[i];
        }
        ss << "]";
        return ss.str();
    }

    /**
     * @brief Redirect logging output to a different stream.
     *
     * @param stream New output stream to use.
     */
    static void setOutputStream(std::ostream& stream) {
        out = &stream;
    }
};

inline bool Logger::enable_logging = false;
inline std::ostream* Logger::out = &std::cout;

#endif // LOGGING_H
