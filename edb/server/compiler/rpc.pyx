#
# This source file is part of the EdgeDB open source project.
#
# Copyright 2024-present MagicStack Inc. and the EdgeDB authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import hashlib
import uuid

cimport cython
import immutables

from edb import edgeql, errors
from edb.common import uuidgen
from edb.edgeql import qltypes
from edb.server import config, defines
from edb.server.pgproto.pgproto cimport WriteBuffer, ReadBuffer

from . import enums, sertypes

cdef object OUT_FMT_BINARY = enums.OutputFormat.BINARY
cdef object OUT_FMT_JSON = enums.OutputFormat.JSON
cdef object OUT_FMT_JSON_ELEMENTS = enums.OutputFormat.JSON_ELEMENTS
cdef object OUT_FMT_NONE = enums.OutputFormat.NONE

cdef object IN_FMT_BINARY = enums.InputFormat.BINARY
cdef object IN_FMT_JSON = enums.InputFormat.JSON

cdef char MASK_NORMALIZED       = 1 << 0
cdef char MASK_JSON_PARAMETERS  = 1 << 1
cdef char MASK_EXPECT_ONE       = 1 << 2
cdef char MASK_INLINE_TYPEIDS   = 1 << 3
cdef char MASK_INLINE_TYPENAMES = 1 << 4
cdef char MASK_INLINE_OBJECTIDS = 1 << 5


cdef char serialize_output_format(val):
    if val is OUT_FMT_BINARY:
        return b'b'
    elif val is OUT_FMT_JSON:
        return b'j'
    elif val is OUT_FMT_JSON_ELEMENTS:
        return b'J'
    elif val is OUT_FMT_NONE:
        return b'n'
    else:
        raise AssertionError("unreachable")


cdef deserialize_output_format(char mode):
    if mode == b'b':
        return OUT_FMT_BINARY
    elif mode == b'j':
        return OUT_FMT_JSON
    elif mode == b'J':
        return OUT_FMT_JSON_ELEMENTS
    elif mode == b'n':
        return OUT_FMT_NONE
    else:
        raise errors.BinaryProtocolError(
            f'unknown output mode "{repr(mode)[2:-1]}"')


@cython.final
cdef class CompileRequest:
    def __cinit__(self, serializer: sertypes.CompilationConfigSerializer):
        self._serializer = serializer

    def update(
        self,
        source: edgeql.Source,
        protocol_version: defines.ProtocolVersion,
        *,
        output_format: enums.OutputFormat = OUT_FMT_BINARY,
        input_format: enums.InputFormat = IN_FMT_BINARY,
        expect_one: bint = False,
        implicit_limit: int = 0,
        inline_typeids: bint = False,
        inline_typenames: bint = False,
        inline_objectids: bint = True,
    ) -> CompileRequest:
        self.query = source.text()
        self.query_hash = source.cache_key()
        self.normalized = isinstance(source, edgeql.NormalizedSource)

        self.protocol_version = protocol_version
        self.output_format = output_format
        self.json_parameters = input_format is IN_FMT_JSON
        self.implicit_limit = implicit_limit
        self.inline_typeids = inline_typeids
        self.inline_typenames = inline_typenames
        self.inline_objectids = inline_objectids

        self.serialized_cache = None
        self.cache_key = None
        return self

    def set_modaliases(self, value) -> CompileRequest:
        self.modaliases = value
        self.serialized_cache = None
        self.cache_key = None
        return self

    def set_session_config(self, value) -> CompileRequest:
        self.session_config = value
        self.serialized_cache = None
        self.cache_key = None
        return self

    def set_system_config(self, value) -> CompileRequest:
        self.system_config = value
        self.serialized_cache = None
        self.cache_key = None
        return self

    def deserialize(
        self, bytes data, cache_key: uuid.UUID | None = None
    ) -> CompileRequest:
        if data[0] == 0:
            self._deserialize_v0(data)
        else:
            raise errors.UnsupportedProtocolVersionError(
                f"unsupported compile cache: version {data[0]}"
            )
        self.cache_key = cache_key
        return self

    def serialize(self) -> bytes:
        if self.serialized_cache is None:
            self._serialize()
        return self.serialized_cache

    def get_cache_key(self) -> uuid.UUID:
        if self.cache_key is None:
            self._serialize()
        return self.cache_key

    cdef _serialize(self):
        cdef:
            char version = 0, flags
            WriteBuffer out = WriteBuffer.new()

        out.write_byte(version)
        out.write_len_prefixed_bytes(self.query_hash)

        flags = (
            (MASK_NORMALIZED if self.normalized else 0) |
            (MASK_JSON_PARAMETERS if self.json_parameters else 0) |
            (MASK_EXPECT_ONE if self.expect_one else 0) |
            (MASK_INLINE_TYPEIDS if self.inline_typeids else 0) |
            (MASK_INLINE_TYPENAMES if self.inline_typenames else 0) |
            (MASK_INLINE_OBJECTIDS if self.inline_objectids else 0)
        )
        out.write_byte(flags)

        out.write_int16(self.protocol_version[0])
        out.write_int16(self.protocol_version[1])
        out.write_byte(serialize_output_format(self.output_format))
        out.write_int64(self.implicit_limit)

        if self.modaliases is None:
            out.write_int32(0)
        else:
            out.write_int32(len(self.modaliases))
            for k, v in sorted(
                self.modaliases.items(),
                key=lambda i: (0, i[0]) if i[0] is None else (1, i[0])
            ):
                if k is None:
                    out.write_byte(0)
                else:
                    out.write_byte(1)
                    out.write_str(k, "utf-8")
                out.write_str(v, "utf-8")

        type_id, desc = self._serializer.describe()
        out.write_bytes(type_id.bytes)
        out.write_len_prefixed_bytes(desc)

        if self.session_config is None:
            session_config = b""
        else:
            session_config = self._serializer.encode(
                {k: v.value for k, v in self.session_config.items()}
            )
        out.write_len_prefixed_bytes(session_config)

        hash_obj = hashlib.blake2b(memoryview(out), digest_size=16)

        # system config only affects the cache key
        if self.system_config is None:
            system_config = b""
        else:
            system_config = self._serializer.encode(
                {k: v.value for k, v in self.system_config.items()}
            )
        hash_obj.update(system_config)

        cache_key_bytes = hash_obj.digest()
        self.cache_key = uuidgen.from_bytes(cache_key_bytes)

        out.write_str(self.query, "utf-8")
        out.write_bytes(cache_key_bytes)
        self.serialized_cache = bytes(out)

    cdef _deserialize_v0(self, bytes data):
        cdef char flags

        self.serialized_cache = data

        buf = ReadBuffer.new_message_parser(data)

        assert buf.read_byte() == 0  # version
        self.query_hash = buf.read_len_prefixed_bytes()

        flags = buf.read_byte()
        self.normalized = flags & MASK_NORMALIZED
        self.json_parameters = flags & MASK_JSON_PARAMETERS
        self.expect_one = flags & MASK_EXPECT_ONE
        self.inline_typeids = flags & MASK_INLINE_TYPEIDS
        self.inline_typenames = flags & MASK_INLINE_TYPENAMES
        self.inline_objectids = flags & MASK_INLINE_OBJECTIDS

        self.protocol_version = buf.read_int16(), buf.read_int16()
        self.output_format = deserialize_output_format(buf.read_byte())
        self.implicit_limit = buf.read_int64()

        size = buf.read_int32()
        modaliases = []
        for _ in range(size):
            if buf.read_byte():
                k = buf.read_null_str().decode("utf-8")
            else:
                k = None
            v = buf.read_null_str().decode("utf-8")
            modaliases.append((k, v))
        self.modaliases = immutables.Map(modaliases)

        type_id = uuidgen.from_bytes(buf.read_bytes(16))
        if type_id == self._serializer.type_id:
            serializer = self._serializer
            buf.read_len_prefixed_bytes()
        else:
            serializer = sertypes.CompilationConfigSerializer(
                type_id, buf.read_len_prefixed_bytes(), self.protocol_version
            )

        data = buf.read_len_prefixed_bytes()
        if data:
            self.session_config = immutables.Map(
                (
                    k,
                    config.SettingValue(
                        name=k,
                        value=v,
                        source='session',
                        scope=qltypes.ConfigScope.SESSION,
                    )
                ) for k, v in serializer.decode(data).items()
            )
        else:
            self.session_config = None

        self.query = buf.read_null_str().decode("utf-8")
        self.cache_key = uuidgen.from_bytes(buf.read_bytes(16))

    def __hash__(self):
        return hash(self.get_cache_key())

    def __eq__(self, other: CompileRequest) -> bool:
        return self.get_cache_key() == other.get_cache_key()