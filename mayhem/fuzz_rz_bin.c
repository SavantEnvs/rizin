#include <rz_bin.h>
#include <rz_util.h>
#include <stdint.h>
#include <string.h>

static volatile size_t sink;

static void touch(const char *s) {
	if (s) {
		sink += strlen(s);
	}
}

static void walk_pvec_symbols(const RzPVector /*<RzBinSymbol *>*/ *v) {
	void **it;
	if (!v) {
		return;
	}
	rz_pvector_foreach (v, it) {
		RzBinSymbol *s = *it;
		char *n = rz_bin_symbol_name(s);
		touch(n);
		free(n);
		touch(s->dname);
		touch(s->libname);
		touch(s->classname);
		touch(s->forwarder);
		touch(s->bind);
		touch(s->type);
	}
}

static void walk_object(RzBinObject *o) {
	void **it;
	const RzBinInfo *info = rz_bin_object_get_info(o);
	if (info) {
		touch(info->file);
		touch(info->type);
		touch(info->arch);
		touch(info->machine);
		touch(info->os);
		touch(info->subsystem);
		touch(info->rpath);
	}
	const RzPVector *entries = rz_bin_object_get_entries(o);
	if (entries) {
		rz_pvector_foreach (entries, it) {
			RzBinAddr *a = *it;
			sink += a->vaddr;
		}
	}
	const RzPVector *imports = rz_bin_object_get_imports(o);
	if (imports) {
		rz_pvector_foreach (imports, it) {
			RzBinImport *i = *it;
			touch(i->name);
			touch(i->dname);
			touch(i->libname);
			touch(i->classname);
			touch(i->descriptor);
		}
	}
	walk_pvec_symbols(rz_bin_object_get_symbols(o));
	const RzPVector *sections = rz_bin_object_get_sections_all(o);
	if (sections) {
		rz_pvector_foreach (sections, it) {
			RzBinSection *s = *it;
			touch(s->name);
			sink += rz_bin_object_p2v(o, s->paddr);
			sink += rz_bin_object_v2p(o, s->vaddr);
		}
	}
	RzPVector *segments = rz_bin_object_get_segments(o);
	rz_pvector_free(segments);
	const RzPVector *maps = rz_bin_object_get_maps(o); // borrowed despite the RZ_OWN annotation
	if (maps) {
		sink += rz_pvector_len(maps);
	}
	const RzPVector *classes = rz_bin_object_get_classes(o);
	if (classes) {
		rz_pvector_foreach (classes, it) {
			RzBinClass *c = *it;
			touch(c->name);
			touch(c->super);
			RzListIter *li;
			RzBinSymbol *m;
			rz_list_foreach (c->methods, li, m) {
				touch(m->name);
			}
		}
	}
	const RzPVector *strings = rz_bin_object_get_strings(o);
	if (strings) {
		rz_pvector_foreach (strings, it) {
			RzBinString *s = *it;
			touch(s->string);
		}
	}
	const RzPVector *libs = rz_bin_object_get_libs(o);
	if (libs) {
		rz_pvector_foreach (libs, it) {
			touch(*it);
		}
	}
	const RzPVector *fields = rz_bin_object_get_fields(o);
	if (fields) {
		rz_pvector_foreach (fields, it) {
			sink += (size_t)*it;
		}
	}
	const RzPVector *resources = rz_bin_object_get_resources(o);
	if (resources) {
		rz_pvector_foreach (resources, it) {
			sink += (size_t)*it;
		}
	}
	sink += rz_bin_object_is_big_endian(o);
	sink += rz_bin_object_is_static(o);
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if (size < 8) {
		return -1;
	}
	RzBin *bin = rz_bin_new();
	if (!bin) {
		return 0;
	}
	bin->use_xtr = true;
	RzBuffer *buf = rz_buf_new_with_bytes(data, size);
	if (!buf) {
		rz_bin_free(bin);
		return 0;
	}
	RzBinOptions opt;
	rz_bin_options_init(&opt, -1, 0, 0, true);
	opt.filename = "fuzz-input";
	RzBinFile *bf = rz_bin_open_buf(bin, buf, &opt);
	if (bf) {
		RzBinObject *o = rz_bin_cur_object(bin);
		if (o) {
			walk_object(o);
		}
	}
	rz_buf_free(buf);
	rz_bin_free(bin);
	return 0;
}
