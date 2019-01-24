// Copyright (c) 2013 Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//     * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//     * Neither the name of Google Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

// stackwalker_ppc64.cc: ppc64-specific stackwalker.
//
// See stackwalker_ppc64.h for documentation.


#include "common/scoped_ptr.h"
#include "processor/stackwalker_ppc64.h"
#include "google_breakpad/processor/call_stack.h"
#include "google_breakpad/processor/memory_region.h"
#include "google_breakpad/processor/stack_frame_cpu.h"
#include "processor/cfi_frame_info.h"
#include "processor/logging.h"

#include <stdio.h>

namespace google_breakpad {


StackwalkerPPC64::StackwalkerPPC64(const SystemInfo* system_info,
                                   const MDRawContextPPC64* context,
                                   MemoryRegion* memory,
                                   const CodeModules* modules,
                                   StackFrameSymbolizer* resolver_helper)
    : Stackwalker(system_info, memory, modules, resolver_helper),
      context_(context) {
}


StackFrame* StackwalkerPPC64::GetContextFrame() {
  if (!context_) {
    BPLOG(ERROR) << "Can't get context frame without context";
    return NULL;
  }

  StackFramePPC64* frame = new StackFramePPC64();

  // The instruction pointer is stored directly in a register, so pull it
  // straight out of the CPU context structure.
  frame->context = *context_;
  frame->context_validity = StackFramePPC64::CONTEXT_VALID_ALL;
  frame->trust = StackFrame::FRAME_TRUST_CONTEXT;
  frame->instruction = frame->context.srr0;

  return frame;
}

StackFramePPC64* StackwalkerPPC64::GetCallerByCFIFrameInfo(
    const vector<StackFrame*> &frames,
    CFIFrameInfo* cfi_frame_info) {
  StackFramePPC64* last_frame = static_cast<StackFramePPC64*>(frames.back());

  static const char* register_names[] = {
    "r0",  "r1",  "r2",  "r3",  "r4",  "r5",  "r6",  "r7",
    "r8",  "r9",  "r10", "r11", "r12", "r13", "r14", "r15",
    "r16", "r17", "r18", "r19", "r20", "r21", "r22", "r23",
    "r24", "r25", "r26", "r27", "r28", "r29", "r30", "r31",
    "srr0", "srr1", "lr", NULL
  };

  // Populate a dictionary with the valid register values in last_frame.
  CFIFrameInfo::RegisterValueMap<uint64_t> callee_registers;
  for (int i = 0; register_names[i]; i++) {
    if (last_frame->context_validity)// & StackFramePPC64::RegisterValidFlag(i))
      callee_registers[register_names[i]] = last_frame->context.gpr[i];
  }

  // Use the STACK CFI data to recover the caller's register values.
  CFIFrameInfo::RegisterValueMap<uint64_t> caller_registers;
  if (!cfi_frame_info->FindCallerRegs(callee_registers, *memory_,
                                      &caller_registers)) {
    return NULL;
  }
  // Construct a new stack frame given the values the CFI recovered.
  scoped_ptr<StackFramePPC64> frame(new StackFramePPC64());
  for (int i = 0; register_names[i]; i++) {
    CFIFrameInfo::RegisterValueMap<uint64_t>::iterator entry =
      caller_registers.find(register_names[i]);
    if (entry != caller_registers.end()) {
      // We recovered the value of this register; fill the context with the
      // value from caller_registers.
      //frame->context_validity |= StackFramePPC64::RegisterValidFlag(i);
      frame->context_validity |= StackFramePPC64::CONTEXT_VALID_ALL;
      frame->context.gpr[i] = entry->second;
    } /*else if (19 <= i && i <= 29 && (last_frame->context_validity &
                                      StackFrameARM64::RegisterValidFlag(i))) {
      // If the STACK CFI data doesn't mention some callee-saves register, and
      // it is valid in the callee, assume the callee has not yet changed it.
      // Registers r19 through r29 are callee-saves, according to the Procedure
      // Call Standard for the ARM AARCH64 Architecture, which the Linux ABI
      // follows.
      frame->context_validity |= StackFrameARM64::RegisterValidFlag(i);
      frame->context.iregs[i] = last_frame->context.iregs[i];
    }*/
  }
  // If the CFI doesn't recover the PC explicitly, then use .ra.
  if (!(frame->context_validity & StackFramePPC64::CONTEXT_VALID_SRR0)) {
    CFIFrameInfo::RegisterValueMap<uint64_t>::iterator entry =
      caller_registers.find(".ra");
    if (entry != caller_registers.end()) {
      frame->context_validity |= StackFramePPC64::CONTEXT_VALID_SRR0;
      frame->context.srr0 = entry->second;
    }
  }
  // If the CFI doesn't recover the SP explicitly, then use .cfa.
  if (!(frame->context_validity & StackFramePPC64::CONTEXT_VALID_GPR1)) {
    CFIFrameInfo::RegisterValueMap<uint64_t>::iterator entry =
      caller_registers.find(".cfa");
    if (entry != caller_registers.end()) {
      frame->context_validity |= StackFramePPC64::CONTEXT_VALID_GPR1;
      frame->context.gpr[1] = entry->second;
    }
  }

  // If we didn't recover the PC and the SP, then the frame isn't very useful.
  static const uint64_t essentials = (StackFramePPC64::CONTEXT_VALID_GPR1
                                     | StackFramePPC64::CONTEXT_VALID_SRR0);
  if ((frame->context_validity & essentials) != essentials)
    return NULL;

  frame->trust = StackFrame::FRAME_TRUST_CFI;
  return frame.release();
}

StackFramePPC64* StackwalkerPPC64::GetCallerByStackScan(
    const vector<StackFrame*> &frames) {
  StackFramePPC64* last_frame = static_cast<StackFramePPC64*>(frames.back());
  uint64_t last_sp = last_frame->context.gpr[1];
  uint64_t caller_sp, caller_pc;

  if (!ScanForReturnAddress(last_sp, &caller_sp, &caller_pc,
                            frames.size() == 1 /* is_context_frame */)) {
    // No plausible return address was found.
    return NULL;
  }

  // ScanForReturnAddress found a reasonable return address. Advance
  // %sp to the location above the one where the return address was
  // found.
  caller_sp += 8;

  // Create a new stack frame (ownership will be transferred to the caller)
  // and fill it in.
  StackFramePPC64* frame = new StackFramePPC64();

  frame->trust = StackFrame::FRAME_TRUST_SCAN;
  frame->context = last_frame->context;
  frame->context.srr0 = caller_pc;
  frame->context.gpr[1] = caller_sp;
  frame->context_validity = StackFramePPC64::CONTEXT_VALID_SRR0 |
                            StackFramePPC64::CONTEXT_VALID_GPR1;

  return frame;
}

StackFramePPC64* StackwalkerPPC64::GetCallerByFramePointer(
    const vector<StackFrame*> &frames) {
  StackFramePPC64* last_frame = static_cast<StackFramePPC64*>(
      frames.back());

  // A caller frame must reside higher in memory than its callee frames.
  // Anything else is an error, or an indication that we've reached the
  // end of the stack.
  uint64_t stack_pointer;
  if (!memory_->GetMemoryAtAddress(last_frame->context.gpr[1],
                                   &stack_pointer) ||
      stack_pointer <= last_frame->context.gpr[1]) {
    return NULL;
  }

  // Mac OS X/Darwin gives 1 as the return address from the bottom-most
  // frame in a stack (a thread's entry point).  I haven't found any
  // documentation on this, but 0 or 1 would be bogus return addresses,
  // so check for them here and return false (end of stack) when they're
  // hit to avoid having a phantom frame.
  uint64_t instruction;
  if (!memory_->GetMemoryAtAddress(stack_pointer + 16, &instruction) ||
      instruction <= 1) {
    return NULL;
  }

  StackFramePPC64* frame = new StackFramePPC64();

  frame->context = last_frame->context;
  frame->context.srr0 = instruction;
  frame->context.gpr[1] = stack_pointer;
  frame->context_validity = StackFramePPC64::CONTEXT_VALID_SRR0 |
                            StackFramePPC64::CONTEXT_VALID_GPR1;
  frame->trust = StackFrame::FRAME_TRUST_FP;

  return frame;
}

StackFrame* StackwalkerPPC64::GetCallerFrame(const CallStack* stack,
                                             bool stack_scan_allowed) {
  if (!memory_ || !stack) {
    BPLOG(ERROR) << "Can't get caller frame without memory or stack";
    return NULL;
  }

  const vector<StackFrame*> &frames = *stack->frames();
  StackFramePPC64* last_frame = static_cast<StackFramePPC64*>(
      stack->frames()->back());
  scoped_ptr<StackFramePPC64> frame;
 
  scoped_ptr<CFIFrameInfo> cfi_frame_info(
      frame_symbolizer_->FindCFIFrameInfo(last_frame));
  if (cfi_frame_info.get())
    frame.reset(GetCallerByCFIFrameInfo(frames, cfi_frame_info.get()));
  
  if (!frame.get()) 
    frame.reset(GetCallerByFramePointer(frames));

  if (stack_scan_allowed && !frame.get())
    frame.reset(GetCallerByStackScan(frames));

  if (!frame.get())
    return NULL;

  // The instruction pointers for previous frames are saved on the stack.
  // The typical ppc64 calling convention is for the called procedure to store
  // its return address in the calling procedure's stack frame at 8(%r1),
  // and to allocate its own stack frame by decrementing %r1 (the stack
  // pointer) and saving the old value of %r1 at 0(%r1).  Because the ppc64 has
  // no hardware stack, there is no distinction between the stack pointer and
  // frame pointer, and what is typically thought of as the frame pointer on
  // an x86 is usually referred to as the stack pointer on a ppc64.


  // Should we terminate the stack walk? (end-of-stack or broken invariant)
  if (TerminateWalk(frame->context.srr0,
                    frame->context.gpr[1],
                    last_frame->context.gpr[1],
                    stack->frames()->size() == 1)) {
    return NULL;
  }

  // frame->context.srr0 is the return address, which is one instruction
  // past the branch that caused us to arrive at the callee.  Set
  // frame_ppc64->instruction to eight less than that.  Since all ppc64
  // instructions are 8 bytes wide, this is the address of the branch
  // instruction.  This allows source line information to match up with the
  // line that contains a function call.  Callers that require the exact
  // return address value may access the context.srr0 field of StackFramePPC64.
  frame->instruction = frame->context.srr0 - 4;

  return frame.release();
}


}  // namespace google_breakpad
