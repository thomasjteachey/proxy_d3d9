#pragma once

// This module was used for earlier experiments with opcode dispatch breakpoints.
// The current implementation lives in hitgate.cpp; the project still references
// this file, so keep a tiny stub to avoid build failures.

namespace DispatchBP
{
    void Install();
    void Remove();
}
