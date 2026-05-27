#pragma once
#include <Windows.h>

typedef enum CREATE_BIND_LINK_FLAGS
{
    CREATE_BIND_LINK_FLAG_NONE = 0x00000000,
    CREATE_BIND_LINK_FLAG_READ_ONLY = 0x00000001,
    CREATE_BIND_LINK_FLAG_MERGED = 0x00000002,
} CREATE_BIND_LINK_FLAGS;

DEFINE_ENUM_FLAG_OPERATORS(CREATE_BIND_LINK_FLAGS);

typedef  HRESULT(__stdcall* PtrCreateBindLink)(
    PVOID jobHandle,
    CREATE_BIND_LINK_FLAGS createBindLinkFlags,
    PCWSTR virtualPath,
    PCWSTR backingPath,
    UINT32 exceptionCount,
    PCWSTR* const exceptionPaths);


typedef  HRESULT(__stdcall* PtrRemoveBindLink)(
    PVOID reserved,
    PCWSTR backingPath);


