// SPDX-FileCopyrightText: 2009-2019 pancake <pancake@nopcode.org>
// SPDX-License-Identifier: LGPL-3.0-only

#include <rz_reg.h>
#include <rz_util.h>

typedef ut32 ut27;
static ut27 rz_read_me27(const ut8 *buf, int boff) {
	ut27 ret = 0;
	rz_mem_copybits_delta((ut8 *)&ret, 18, buf, boff, 9);
	rz_mem_copybits_delta((ut8 *)&ret, 9, buf, boff + 9, 9);
	rz_mem_copybits_delta((ut8 *)&ret, 0, buf, boff + 18, 9);
	return ret;
}

RZ_API ut64 rz_reg_get_value_big(RzReg *reg, RzRegItem *item, utX *val) {
	rz_return_val_if_fail(reg && item, 0);

	ut64 ret = 0LL;
	int off = BITS2BYTES(item->offset);
	RzRegSet *regset = &reg->regset[item->arena];
	if (!regset->arena) {
		return 0LL;
	}
	switch (item->size) {
	case 80: // word + qword
		if (regset->arena->bytes && (off + 10 <= regset->arena->size)) {
			val->v80.Low = *((ut64 *)(regset->arena->bytes + off));
			val->v80.High = *((ut16 *)(regset->arena->bytes + off + 8));
		} else {
			eprintf("rz_reg_get_value: null or oob arena for current regset\n");
		}
		ret = val->v80.Low;
		break;
	case 96: // dword + qword
		if (regset->arena->bytes && (off + 12 <= regset->arena->size)) {
			val->v96.Low = *((ut64 *)(regset->arena->bytes + off));
			val->v96.High = *((ut32 *)(regset->arena->bytes + off + 8));
		} else {
			eprintf("rz_reg_get_value: null or oob arena for current regset\n");
		}
		ret = val->v96.Low;
		break;
	case 128: // qword + qword
		if (regset->arena->bytes && (off + 16 <= regset->arena->size)) {
			val->v128.Low = *((ut64 *)(regset->arena->bytes + off));
			val->v128.High = *((ut64 *)(regset->arena->bytes + off + 8));
		} else {
			eprintf("rz_reg_get_value: null or oob arena for current regset\n");
		}
		ret = val->v128.Low;
		break;
	case 256: // qword + qword + qword + qword
		if (regset->arena->bytes && (off + 32 <= regset->arena->size)) {
			val->v256.Low.Low = *((ut64 *)(regset->arena->bytes + off));
			val->v256.Low.High = *((ut64 *)(regset->arena->bytes + off + 8));
			val->v256.High.Low = *((ut64 *)(regset->arena->bytes + off + 16));
			val->v256.High.High = *((ut64 *)(regset->arena->bytes + off + 24));
		} else {
			eprintf("rz_reg_get_value: null or oob arena for current regset\n");
		}
		ret = val->v256.Low.Low;
		break;
	default:
		break;
	}
	return ret;
}

RZ_API ut64 rz_reg_get_value(RzReg *reg, RzRegItem *item) {
	rz_return_val_if_fail(reg && item, 0);
	if (!reg || !item || item->offset == -1) {
		return 0LL;
	}
	int off = BITS2BYTES(item->offset);
	RzRegSet *regset = &reg->regset[item->arena];
	if (!regset->arena) {
		return 0LL;
	}
	switch (item->size) {
	case 1: {
		int offset = item->offset / 8;
		if (offset >= regset->arena->size) {
			break;
		}
		return (regset->arena->bytes[offset] &
			       (1 << (item->offset % 8)))
			? 1
			: 0;
	} break;
	case 4:
		if (regset->arena->size - off - 1 >= 0) {
			return (rz_read_at_ble8(regset->arena->bytes, off)) & 0xF;
		}
		break;
	case 8:
		if (regset->arena->size - off - 1 >= 0) {
			return rz_read_at_ble8(regset->arena->bytes, off);
		}
		break;
	case 16:
		if (regset->arena->size - off - 2 >= 0) {
			return rz_read_ble16(regset->arena->bytes + off, reg->big_endian);
		}
		break;
	case 27:
		if (off + 3 < regset->arena->size) {
			return rz_read_me27(regset->arena->bytes + off, 0);
		}
		break;
	case 32:
		if (off + 4 <= regset->arena->size) {
			return rz_read_ble32(regset->arena->bytes + off, reg->big_endian);
		}
		eprintf("rz_reg_get_value: 32bit oob read %d\n", off);
		break;
	case 64:
		if (regset->arena && regset->arena->bytes && (off + 8 <= regset->arena->size)) {
			return rz_read_ble64(regset->arena->bytes + off, reg->big_endian);
		}
		// eprintf ("rz_reg_get_value: null or oob arena for current regset\n");
		break;
	case 80: // long double
	case 96: // long floating value
		// FIXME: It is a precision loss, please implement me properly!
		return (ut64)rz_reg_get_longdouble(reg, item);
	case 128:
	case 256:
		// XXX 128 & 256 bit
		return (ut64)rz_reg_get_longdouble(reg, item);
	default:
		break;
	}
	return 0LL;
}

RZ_API ut64 rz_reg_get_value_by_role(RzReg *reg, RzRegisterId role) {
	// TODO use mapping from RzRegisterId to RzRegItem (via RzRegSet)
	return rz_reg_get_value(reg, rz_reg_get(reg, rz_reg_get_name(reg, role), -1));
}

RZ_API bool rz_reg_set_value(RzReg *reg, RzRegItem *item, ut64 value) {
	ut8 bytes[12];
	ut8 *src = bytes;
	rz_return_val_if_fail(reg && item, false);

	if (rz_reg_is_readonly(reg, item)) {
		return true;
	}
	if (item->offset < 0) {
		return true;
	}
	RzRegArena *arena = reg->regset[item->arena].arena;
	if (!arena) {
		return false;
	}
	switch (item->size) {
	case 80:
	case 96: // long floating value
		rz_reg_set_longdouble(reg, item, (long double)value);
		break;
	case 64:
		if (reg->big_endian) {
			rz_write_be64(src, value);
		} else {
			rz_write_le64(src, value);
		}
		break;
	case 32:
		if (reg->big_endian) {
			rz_write_be32(src, value);
		} else {
			rz_write_le32(src, value);
		}
		break;
	case 16:
		if (reg->big_endian) {
			rz_write_be16(src, value);
		} else {
			rz_write_le16(src, value);
		}
		break;
	case 8:
		rz_write_ble8(src, (ut8)(value & UT8_MAX));
		break;
	case 1:
		if (value) {
			ut8 *buf = arena->bytes + (item->offset / 8);
			int bit = (item->offset % 8);
			ut8 mask = (1 << bit);
			buf[0] = (buf[0] & (0xff ^ mask)) | mask;
		} else {
			int idx = item->offset / 8;
			if (idx + item->size > arena->size) {
				eprintf("RzRegSetOverflow %d vs %d\n", idx + item->size, arena->size);
				return false;
			}
			ut8 *buf = arena->bytes + idx;
			int bit = item->offset % 8;
			ut8 mask = 0xff ^ (1 << bit);
			buf[0] = (buf[0] & mask) | 0;
		}
		return true;
	case 128:
	case 256:
		// XXX 128 & 256 bit
		return false; // (ut64)rz_reg_get_longdouble (reg, item);
	default:
		eprintf("rz_reg_set_value: Bit size %d not supported\n", item->size);
		return false;
	}
	const bool fits_in_arena = (arena->size - BITS2BYTES(item->offset) - BITS2BYTES(item->size)) >= 0;
	if (src && fits_in_arena) {
		rz_mem_copybits(reg->regset[item->arena].arena->bytes +
				BITS2BYTES(item->offset),
			src, item->size);
		return true;
	}
	eprintf("rz_reg_set_value: Cannot set %s to 0x%" PFMT64x "\n", item->name, value);
	return false;
}

RZ_API bool rz_reg_set_value_by_role(RzReg *reg, RzRegisterId role, ut64 val) {
	// TODO use mapping from RzRegisterId to RzRegItem (via RzRegSet)
	const char *name = rz_reg_get_name(reg, role);
	if (!name) {
		return false;
	}
	RzRegItem *r = rz_reg_get(reg, name, -1);
	return rz_reg_set_value(reg, r, val);
}

RZ_API ut64 rz_reg_set_bvalue(RzReg *reg, RzRegItem *item, const char *str) {
	ut64 num = UT64_MAX;
	if (item && item->flags && str) {
		num = rz_str_bits_from_string(str, item->flags);
		if (num == UT64_MAX) {
			num = rz_num_math(NULL, str);
		}
		rz_reg_set_value(reg, item, num);
	}
	return num;
}

RZ_API RZ_HEAP char *rz_reg_get_bvalue(RzReg *reg, RzRegItem *item) {
	char *out = NULL;
	if (reg && item && item->flags) {
		out = malloc(strlen(item->flags) + 1);
		if (out) {
			ut64 num = rz_reg_get_value(reg, item);
			rz_str_bits(out, (ut8 *)&num,
				strlen(item->flags) * 8, item->flags);
		}
	}
	return out;
}

/* packed registers */
// packbits can be 8, 16, 32 or 64
// result value is always casted into ut64
// TODO: support packbits=128 for xmm registers
RZ_API ut64 rz_reg_get_pack(RzReg *reg, RzRegItem *item, int packidx, int packbits) {
	rz_return_val_if_fail(reg && item, 0LL);

	if (packbits < 1) {
		packbits = item->packed_size;
	}
	if (packbits > 64) {
		packbits = 64;
		eprintf("Does not support pack bits > 64\n");
	}

	ut64 ret = 0LL;
	const int packbytes = packbits / 8;
	const int packmod = packbits % 8;
	if (packmod) {
		eprintf("Invalid bit size for packet register\n");
		return 0LL;
	}
	if ((packidx + 1) * packbits > item->size) {
		eprintf("Packed index is beyond the register size\n");
		return 0LL;
	}
	RzRegSet *regset = &reg->regset[item->arena];
	if (!regset->arena) {
		return 0LL;
	}
	int off = BITS2BYTES(item->offset);
	off += (packidx * packbytes);
	if (regset->arena->size - off - 1 >= 0) {
		int i;
		for (i = packbytes - 1; i >= 0; i--) {
			ret = (ret << 8) | regset->arena->bytes[off + i];
		}
	}
	return ret;
}

// TODO: support packbits=128 for xmm registers
RZ_API int rz_reg_set_pack(RzReg *reg, RzRegItem *item, int packidx, int packbits, ut64 val) {
	rz_return_val_if_fail(reg && reg->regset->arena && item, false);

	if (packbits < 1) {
		packbits = item->packed_size;
	}
	if (packbits > 64) {
		packbits = 64;
		eprintf("Does not support pack bits > 64\n");
	}

	int packbytes = packbits / 8;
	if ((packidx + 1) * packbits > item->size) {
		eprintf("Packed index is beyond the register size\n");
		return false;
	}
	int off = BITS2BYTES(item->offset);
	off += (packidx * packbytes);
	if (reg->regset[item->arena].arena->size - BITS2BYTES(off) - BITS2BYTES(packbytes) >= 0) {
		ut8 *dst = reg->regset[item->arena].arena->bytes + off;
		int i;
		for (i = 0; i < packbytes; i++, val >>= 8) {
			dst[i] = val & 0xff;
		}
		return true;
	}
	eprintf("rz_reg_set_value: Cannot set %s to 0x%" PFMT64x "\n", item->name, val);
	return false;
}
