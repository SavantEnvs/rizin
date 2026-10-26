#include <rz_asm.h>
#include <rz_util.h>
#include <stdint.h>
#include <string.h>

static const char *const archs[] = {
	"x86", "arm", "mips", "ppc", "riscv", "sh", "avr", "6502", "8051", "bf", "dalvik", "java", "wasm",
	"m68k", "msp430", "sparc", "z80", "v850", "xtensa", "tricore", "hexagon", "cil", "lm32", "h8300",
	"i8080", "bpf", "arc", "rx", "pic", "gb", "snes", "tms320", "vax", "or1k", "ebc", "mcs96", "chip8",
};
static const int bitses[] = { 8, 16, 32, 64 };

static RzAsm *as;
static volatile size_t sink;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	as = rz_asm_new();
	return as ? 0 : -1;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 4) {
		return -1;
	}
	const char *arch = archs[data[0] % RZ_ARRAY_SIZE(archs)];
	int bits = bitses[(data[1] >> 1) & 3];
	bool big = data[1] & 1;
	if (!rz_asm_setup(as, arch, bits, big)) {
		return 0;
	}
	rz_asm_set_pc(as, 0x1000);
	const ut8 *buf = data + 2;
	int len = (int)(size - 2);
	size_t off = 0;
	for (int n = 0; n < 64 && (int)off < len; n++) {
		RzAsmOp op;
		rz_asm_op_init(&op);
		int r = rz_asm_disassemble(as, &op, buf + off, len - (int)off);
		if (r > 0) {
			const char *s = rz_asm_op_get_asm(&op);
			if (s) {
				sink += strlen(s);
				RzAsmTokenString *ts = rz_asm_token_string_new(s);
				rz_asm_token_string_free(ts);
			}
		}
		rz_asm_op_fini(&op);
		off += r > 0 ? r : 1;
	}
	return 0;
}
