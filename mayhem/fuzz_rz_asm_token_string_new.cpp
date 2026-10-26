#include <stdint.h>
#include <stddef.h>
#include <string>

extern "C" {
#include "rz_asm.h"
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	std::string str(reinterpret_cast<const char *>(data), size);
	RzAsmTokenString *ts = rz_asm_token_string_new(str.c_str());
	rz_asm_token_string_free(ts);
	return 0;
}
