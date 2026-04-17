## 2024-05-15 - [rsyslog]
**Vulnerability:** The codebase contains instances of `strcpy` and `sprintf` which can lead to buffer overflows.
**Learning:** `strcpy` and `sprintf` are unsafe because they do not check the length of the destination buffer, which can cause buffer overflows if the source string is longer than the destination buffer.
**Prevention:** Use safer alternatives like `strncpy`, `strlcpy`, or `snprintf` which allow specifying the maximum number of characters to copy.
