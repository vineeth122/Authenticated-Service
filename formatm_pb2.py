# Generated by the protocol buffer compiler.  DO NOT EDIT!
# source: test.proto

import sys
_b=sys.version_info[0]<3 and (lambda x:x) or (lambda x:x.encode('latin1'))
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from google.protobuf import reflection as _reflection
from google.protobuf import symbol_database as _symbol_database
# @@protoc_insertion_point(imports)

_sym_db = _symbol_database.Default()




DESCRIPTOR = _descriptor.FileDescriptor(
  name='test.proto',
  package='',
  syntax='proto3',
  serialized_options=None,
  serialized_pb=_b('\n\ntest.proto\"\x80\x01\n\x07Request\x12\x1c\n\x04stop\x18\x01 \x01(\x0b\x32\x0c.StopRequestH\x00\x12(\n\x05reset\x18\x02 \x01(\x0b\x32\x17.ResetBlockListsRequestH\x00\x12\"\n\x04\x65xpr\x18\x03 \x01(\x0b\x32\x12.ExpressionRequestH\x00\x42\t\n\x07request\"\r\n\x0bStopRequest\"\x18\n\x16ResetBlockListsRequest\"K\n\x11\x45xpressionRequest\x12\x10\n\x08username\x18\x01 \x01(\t\x12\x10\n\x08password\x18\x02 \x01(\t\x12\x12\n\nexpression\x18\x03 \x01(\t\"\x85\x01\n\x08Response\x12\x1d\n\x04stop\x18\x01 \x01(\x0b\x32\r.StopResponseH\x00\x12)\n\x05reset\x18\x02 \x01(\x0b\x32\x18.ResetBlockListsResponseH\x00\x12#\n\x04\x65xpr\x18\x03 \x01(\x0b\x32\x13.ExpressionResponseH\x00\x42\n\n\x08response\"\x0e\n\x0cStopResponse\"\x19\n\x17ResetBlockListsResponse\";\n\x12\x45xpressionResponse\x12\x15\n\rauthenticated\x18\x01 \x01(\x08\x12\x0e\n\x06result\x18\x02 \x01(\tb\x06proto3')
)




_REQUEST = _descriptor.Descriptor(
  name='Request',
  full_name='Request',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='stop', full_name='Request.stop', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='reset', full_name='Request.reset', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='expr', full_name='Request.expr', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='request', full_name='Request.request',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=15,
  serialized_end=143,
)


_STOPREQUEST = _descriptor.Descriptor(
  name='StopRequest',
  full_name='StopRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=145,
  serialized_end=158,
)


_RESETBLOCKLISTSREQUEST = _descriptor.Descriptor(
  name='ResetBlockListsRequest',
  full_name='ResetBlockListsRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=160,
  serialized_end=184,
)


_EXPRESSIONREQUEST = _descriptor.Descriptor(
  name='ExpressionRequest',
  full_name='ExpressionRequest',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='username', full_name='ExpressionRequest.username', index=0,
      number=1, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='password', full_name='ExpressionRequest.password', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='expression', full_name='ExpressionRequest.expression', index=2,
      number=3, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=186,
  serialized_end=261,
)


_RESPONSE = _descriptor.Descriptor(
  name='Response',
  full_name='Response',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='stop', full_name='Response.stop', index=0,
      number=1, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='reset', full_name='Response.reset', index=1,
      number=2, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='expr', full_name='Response.expr', index=2,
      number=3, type=11, cpp_type=10, label=1,
      has_default_value=False, default_value=None,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
    _descriptor.OneofDescriptor(
      name='response', full_name='Response.response',
      index=0, containing_type=None, fields=[]),
  ],
  serialized_start=264,
  serialized_end=397,
)


_STOPRESPONSE = _descriptor.Descriptor(
  name='StopResponse',
  full_name='StopResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=399,
  serialized_end=413,
)


_RESETBLOCKLISTSRESPONSE = _descriptor.Descriptor(
  name='ResetBlockListsResponse',
  full_name='ResetBlockListsResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=415,
  serialized_end=440,
)


_EXPRESSIONRESPONSE = _descriptor.Descriptor(
  name='ExpressionResponse',
  full_name='ExpressionResponse',
  filename=None,
  file=DESCRIPTOR,
  containing_type=None,
  fields=[
    _descriptor.FieldDescriptor(
      name='authenticated', full_name='ExpressionResponse.authenticated', index=0,
      number=1, type=8, cpp_type=7, label=1,
      has_default_value=False, default_value=False,
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
    _descriptor.FieldDescriptor(
      name='result', full_name='ExpressionResponse.result', index=1,
      number=2, type=9, cpp_type=9, label=1,
      has_default_value=False, default_value=_b("").decode('utf-8'),
      message_type=None, enum_type=None, containing_type=None,
      is_extension=False, extension_scope=None,
      serialized_options=None, file=DESCRIPTOR),
  ],
  extensions=[
  ],
  nested_types=[],
  enum_types=[
  ],
  serialized_options=None,
  is_extendable=False,
  syntax='proto3',
  extension_ranges=[],
  oneofs=[
  ],
  serialized_start=442,
  serialized_end=501,
)

_REQUEST.fields_by_name['stop'].message_type = _STOPREQUEST
_REQUEST.fields_by_name['reset'].message_type = _RESETBLOCKLISTSREQUEST
_REQUEST.fields_by_name['expr'].message_type = _EXPRESSIONREQUEST
_REQUEST.oneofs_by_name['request'].fields.append(
  _REQUEST.fields_by_name['stop'])
_REQUEST.fields_by_name['stop'].containing_oneof = _REQUEST.oneofs_by_name['request']
_REQUEST.oneofs_by_name['request'].fields.append(
  _REQUEST.fields_by_name['reset'])
_REQUEST.fields_by_name['reset'].containing_oneof = _REQUEST.oneofs_by_name['request']
_REQUEST.oneofs_by_name['request'].fields.append(
  _REQUEST.fields_by_name['expr'])
_REQUEST.fields_by_name['expr'].containing_oneof = _REQUEST.oneofs_by_name['request']
_RESPONSE.fields_by_name['stop'].message_type = _STOPRESPONSE
_RESPONSE.fields_by_name['reset'].message_type = _RESETBLOCKLISTSRESPONSE
_RESPONSE.fields_by_name['expr'].message_type = _EXPRESSIONRESPONSE
_RESPONSE.oneofs_by_name['response'].fields.append(
  _RESPONSE.fields_by_name['stop'])
_RESPONSE.fields_by_name['stop'].containing_oneof = _RESPONSE.oneofs_by_name['response']
_RESPONSE.oneofs_by_name['response'].fields.append(
  _RESPONSE.fields_by_name['reset'])
_RESPONSE.fields_by_name['reset'].containing_oneof = _RESPONSE.oneofs_by_name['response']
_RESPONSE.oneofs_by_name['response'].fields.append(
  _RESPONSE.fields_by_name['expr'])
_RESPONSE.fields_by_name['expr'].containing_oneof = _RESPONSE.oneofs_by_name['response']
DESCRIPTOR.message_types_by_name['Request'] = _REQUEST
DESCRIPTOR.message_types_by_name['StopRequest'] = _STOPREQUEST
DESCRIPTOR.message_types_by_name['ResetBlockListsRequest'] = _RESETBLOCKLISTSREQUEST
DESCRIPTOR.message_types_by_name['ExpressionRequest'] = _EXPRESSIONREQUEST
DESCRIPTOR.message_types_by_name['Response'] = _RESPONSE
DESCRIPTOR.message_types_by_name['StopResponse'] = _STOPRESPONSE
DESCRIPTOR.message_types_by_name['ResetBlockListsResponse'] = _RESETBLOCKLISTSRESPONSE
DESCRIPTOR.message_types_by_name['ExpressionResponse'] = _EXPRESSIONRESPONSE
_sym_db.RegisterFileDescriptor(DESCRIPTOR)

Request = _reflection.GeneratedProtocolMessageType('Request', (_message.Message,), dict(
  DESCRIPTOR = _REQUEST,
  __module__ = 'test_pb2'
  # @@protoc_insertion_point(class_scope:Request)
  ))
_sym_db.RegisterMessage(Request)

StopRequest = _reflection.GeneratedProtocolMessageType('StopRequest', (_message.Message,), dict(
  DESCRIPTOR = _STOPREQUEST,
  __module__ = 'test_pb2'
  # @@protoc_insertion_point(class_scope:StopRequest)
  ))
_sym_db.RegisterMessage(StopRequest)

ResetBlockListsRequest = _reflection.GeneratedProtocolMessageType('ResetBlockListsRequest', (_message.Message,), dict(
  DESCRIPTOR = _RESETBLOCKLISTSREQUEST,
  __module__ = 'test_pb2'
  # @@protoc_insertion_point(class_scope:ResetBlockListsRequest)
  ))
_sym_db.RegisterMessage(ResetBlockListsRequest)

ExpressionRequest = _reflection.GeneratedProtocolMessageType('ExpressionRequest', (_message.Message,), dict(
  DESCRIPTOR = _EXPRESSIONREQUEST,
  __module__ = 'test_pb2'
  # @@protoc_insertion_point(class_scope:ExpressionRequest)
  ))
_sym_db.RegisterMessage(ExpressionRequest)

Response = _reflection.GeneratedProtocolMessageType('Response', (_message.Message,), dict(
  DESCRIPTOR = _RESPONSE,
  __module__ = 'test_pb2'
  # @@protoc_insertion_point(class_scope:Response)
  ))
_sym_db.RegisterMessage(Response)

StopResponse = _reflection.GeneratedProtocolMessageType('StopResponse', (_message.Message,), dict(
  DESCRIPTOR = _STOPRESPONSE,
  __module__ = 'test_pb2'
  # @@protoc_insertion_point(class_scope:StopResponse)
  ))
_sym_db.RegisterMessage(StopResponse)

ResetBlockListsResponse = _reflection.GeneratedProtocolMessageType('ResetBlockListsResponse', (_message.Message,), dict(
  DESCRIPTOR = _RESETBLOCKLISTSRESPONSE,
  __module__ = 'test_pb2'
  # @@protoc_insertion_point(class_scope:ResetBlockListsResponse)
  ))
_sym_db.RegisterMessage(ResetBlockListsResponse)

ExpressionResponse = _reflection.GeneratedProtocolMessageType('ExpressionResponse', (_message.Message,), dict(
  DESCRIPTOR = _EXPRESSIONRESPONSE,
  __module__ = 'test_pb2'
  # @@protoc_insertion_point(class_scope:ExpressionResponse)
  ))
_sym_db.RegisterMessage(ExpressionResponse)


# @@protoc_insertion_point(module_scope)
