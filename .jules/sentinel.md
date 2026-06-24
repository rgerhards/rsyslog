## 2025-02-12 - Excessive Stack Allocation in Message Parsing
**Vulnerability:** The function `jsonAddVal_escaped` in `runtime/msg.c` allocated a 100KB buffer on the stack (`uchar wrkbuf[100000]`), posing a risk of stack overflow (DoS) in constrained environments or deep call stacks.
**Learning:** Legacy code optimization attempts (avoiding malloc) can sometimes introduce security risks like excessive stack usage if not bounded correctly.
**Prevention:** Limit stack buffers to a reasonable size (e.g., 4KB) and implement fallbacks to heap allocation for larger data, as was already partially present but with an unsafe threshold.
