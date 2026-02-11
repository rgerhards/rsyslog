## 2024-05-24 - Buffer Overflow via VLA in String Helpers
**Vulnerability:** Found a helper function `str_split` in `mmdblookup` using a Variable Length Array (VLA) `char tempbuf[strlen(buf)]` to process potentially large external strings. This causes stack overflow. Additionally, logic appended to the buffer (e.g., `}` -> `},`) without resizing, leading to buffer overflow.
**Learning:** VLAs are dangerous for processing external input where size is not strictly bounded. Helper functions doing string manipulation must account for expansion and use heap allocation.
**Prevention:** Always use heap allocation (`malloc`/`CHKmalloc`) for string buffers derived from external input. Avoid `strcat` loops; use pointer arithmetic or string builders.
