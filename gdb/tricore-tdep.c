/* Target-dependent code for Infineon TriCore.

   Copyright (C) 2009-2020 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

#include "defs.h"
#include "arch-utils.h"
#include "dis-asm.h"
#include "frame.h"
#include "trad-frame.h"
#include "symtab.h"
#include "value.h"
#include "gdbcmd.h"
#include "gdbcore.h"
#include "breakpoint.h"
#include "inferior.h"
#include "regcache.h"
#include "target.h"
#include "frame-base.h"
#include "frame-unwind.h"
#include "dwarf2/frame.h"
#include "osabi.h"
#include "target-descriptions.h"
#include "tricore-tdep.h"
#include "remote.h"
#include "elf-bfd.h"
#include "elf/tricore.h"
#include "tricore.h"
#include "objfiles.h"
#include "gdbtypes.h"
#include "gdbarch.h"
#include "opcodes/disassemble.h"
#include "features/tricore.c"
#include <inttypes.h>

#define __VIRTUAL_IO__

#ifdef __VIRTUAL_IO__
#include "gdbsupport/fileio.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#endif

#define TRICORE_BREAKPOINT      {0x00, 0xa0} /* debug */
constexpr gdb_byte tricore_break_insn[] = TRICORE_BREAKPOINT;
typedef BP_MANIPULATION (tricore_break_insn) tricore_breakpoint;
#undef NULL
#define NULL 0
/* The registers of the Infineon TriCore processor.  */

static const char *tricore_register_names[] =
{
    "d0", "d1", "d2",  "d3",  "d4",  "d5",  "d6",  "d7",
    "d8", "d9", "d10", "d11", "d12", "d13", "d14", "d15",
    "a0", "a1", "a2",  "a3",  "a4",  "a5",  "a6",  "a7",
    "a8", "a9", "a10", "a11", "a12", "a13", "a14", "a15",
    "lcx", "fcx", "pcxi", "psw", "pc", "icr", "isp",
    "btv", "biv", "syscon", "pmucon0", "dmucon"
};


struct tricore_frame_cache
{
//  /* Base address.  */
  CORE_ADDR base;
  CORE_ADDR pc;
  CORE_ADDR frame_regs[TRICORE_NUM_REGS];
  CORE_ADDR frame_func;
//  /* Flag showing that a frame has been created in the prologue code.  */
//  int uses_fp;
//  /* Saved registers.  */
  struct trad_frame_saved_reg *saved_regs;
  enum unwind_stop_reason unwind_reason;
};

static unsigned int tricore_debug = 0;

static const char *
tricore_register_name (struct gdbarch *gdbarch, int regnum)
{
  if (regnum >= 0 && regnum < TRICORE_NUM_REGS)
    return tricore_register_names[regnum];
  return NULL;
}

/* Which instruction set architecure do we use?  */

static tricore_isa current_isa = TRICORE_V1_6_2;

/* Check what ISA is actually in use.  */

static void
tricore_find_isa (struct gdbarch_info *info)
{
  unsigned long mask;

  if (info->abfd == NULL)
    return;

  mask = EF_EABI_TRICORE_V1_6_2;
  current_isa = TRICORE_V1_6_2;
  switch (mask & EF_EABI_TRICORE_CORE_MASK)
    {
      case EF_EABI_TRICORE_V1_1:
        current_isa=TRICORE_V1_1;
        break;
      case EF_EABI_TRICORE_V1_2:
        current_isa=TRICORE_V1_2;
        break;
      case EF_EABI_TRICORE_V1_3:
        current_isa=TRICORE_V1_3;
        break;
      case EF_EABI_TRICORE_V1_3_1:
        current_isa=TRICORE_V1_3_1;
        break;
      case EF_EABI_TRICORE_V1_6:
        current_isa=TRICORE_V1_6;
        break;
      case EF_EABI_TRICORE_V1_6_1:
        current_isa=TRICORE_V1_6_1;
        break;
      case EF_EABI_TRICORE_V1_6_2:
        current_isa=TRICORE_V1_6_2;
        break;
      default:
	error ("Unknown TriCore ISA in ELF header detected.");
    }
}

/* Find the first real insn of the function starting at PC.  On the
   TriCore, a prologue (as produced by gcc) looks like this:

   > If the workaround for Rider-D's cpu13 bug is enabled:
       dsync                    0480000d
     If additonally the workaround for Rider-B/D's cpu9 bug is enabled:
       nop                      0000
       nop                      0000
     or
       nop                      0000000d
       nop                      0000000d

   > If the frame pointer (%a1) is used:
       st.a [+%sp]-8,%ax        f5b8ax89

       mov.aa %ax,%sp           ax80      RIDER-A only
     or
       mov.aa %ax,%sp           ax40      RIDER-B/D only
     or
       mov.aa %ax,%sp           x000a001

   > If space is needed to store local variables on the stack:
       sub.a %sp,const8         xx40      RIDER-A only
     or
       sub.a %sp,const8         xx20      RIDER-B/D only
     or
       lea %sp,[%sp]const16     xxxxaad9
     or
       movh.a %a15,const16      fxxxx091
       (lea %a15,[%a15]const16  xxxxffd9) if const16 != 0
       sub.a %sp,%sp,%a15       a020fa01

   > If the TOC pointer (%a12) needs to be loaded:
       movh.a %a12,hi:toc       cxxxx091
       lea %a12,[%a12]lo:toc    xxxxccd9

   > If this is main, then __main is called:
       call __main              xxxxxx6d

   Note that registers are not saved explicitly, as this is done
   automatically by the call insn.  */



static CORE_ADDR
tricore_skip_prologue (struct gdbarch *gdbarch, CORE_ADDR pc)
{
  CORE_ADDR func_addr, func_end;

  /* See what the symbol table says.  */
  if (tricore_debug)
     fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue (0x%08lx)\n", pc);
    const char *func_name;
/* some debug outputs to better understand skip prologue */
//    fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue (0x%08lx)\n", pc);
//    fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue find_pc_partial function %d\n", find_pc_partial_function (pc, &func_name, &func_addr, NULL));
//    fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue func_addr(0x%08lx)\n", func_addr);
//    if (find_pc_partial_function (pc, &func_name, &func_addr, NULL))
//      {
//        /* Found a function.  */
//        fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue find_pc_partial function 1\n");
//        CORE_ADDR postprologue_pc
//    	= skip_prologue_using_sal (gdbarch, func_addr);
//        fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue func_addr(0x%08lx) postprologue_pc(0x%08lx) \n", func_addr,postprologue_pc);
//        CORE_ADDR limit_pc = skip_prologue_using_sal (gdbarch, pc);
//        fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue limit_pc(0x%08lx)\n", limit_pc);
//      }
//    else
//    {
//        CORE_ADDR limit_pc = skip_prologue_using_sal (gdbarch, pc);
//        fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue limit_pc(0x%08lx)\n", limit_pc);
//    }


    if (find_pc_partial_function (pc, &func_name, &func_addr, NULL))
      {
        /* Found a function.  */
        CORE_ADDR postprologue_pc
    	= skip_prologue_using_sal (gdbarch, func_addr);

        if (postprologue_pc != 0)
    	return std::max (pc, postprologue_pc);
      }

    /* No prologue info in symbol table, have to analyze prologue.  */

    /* Find an upper limit on the function prologue using the debug
       information.  If there is no debug information about prologue end, then
       skip_prologue_using_sal will return 0.  */
    CORE_ADDR limit_pc = skip_prologue_using_sal (gdbarch, pc);

    if (tricore_debug)
    	fprintf_unfiltered (gdb_stdlog,"*** Begin tricore_skip_prologue %8.8lx %8.8lx \n",pc,limit_pc);

  if (find_pc_partial_function (pc, NULL, &func_addr, &func_end))
    {
      struct symtab_and_line sal;
      //fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue partial function func_addr (0x%08lx) func_end (0x%08lx)\n", func_addr,func_end);
      sal = find_pc_line (func_addr, 0);
      //fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue partial function sal.line (%d) sal.end (0x%08lx)\n", sal.line,sal.end);
      if (sal.line != 0 && sal.end < func_end)
        {
          if (tricore_debug)
             fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue partial function sal.end (0x%08lx)\n", sal.end);
          return sal.end;
        }

      /* Either there's no line info, or the line after the prologue is after
         the end of the function.  In this case, there probably isn't a
         prologue.  */
//      if (tricore_debug)
//         fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue partial function (0x%08lx)\n", pc);
//      return pc;
    }
  /* We can't find the start of this function, so there's nothing we
     can do.  */
//  if (tricore_debug)
//     fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue no start of function (0x%08lx)\n", pc);
//  return pc;
//TODO
  //has to be reworked and adapted, used when no frame info is avaialble
#if 1
  CORE_ADDR insn;
  CORE_ADDR main_pc, __main_pc, offset;
  struct symtab_and_line sal;
  struct bound_minimal_symbol sym;
  struct gdbarch_tdep *tdep = gdbarch_tdep (gdbarch);
  struct gdbarch_info *info =tdep->info;

  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue (0x%08lx) = ", pc);

  tricore_find_isa (info);

  /* Check if PC points to main ().  */
  main_pc = __main_pc = (CORE_ADDR) 0;
  sym = lookup_minimal_symbol_text ("main", (struct objfile *) NULL);
  if (sym.minsym)
    {
      if (BMSYMBOL_VALUE_ADDRESS (sym) == pc)
        {
          main_pc = pc;
          sym = lookup_minimal_symbol_text ("__main",
                                            (struct objfile *) NULL);
          if (sym.minsym)
            __main_pc = BMSYMBOL_VALUE_ADDRESS (sym);
        }
    }

  insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
  if (tricore_debug) fprintf_unfiltered (gdb_stdlog, "*** tricore_skip_prologue insn1 (0x%08lx)  \n ", insn);
#define RIDER_A 0
#define RIDER_B 1

  if (((insn & 0xf0ff) == 0xa040)) /* mov.aa %an,%sp  */
    {
      pc += 2;
      insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
      if (tricore_debug)
        fprintf_unfiltered (gdb_stdlog, "0x%08lx\n", pc);
      return pc;
    }

  /* Handle stack and frame pointer manipulation.  */
  if (RIDER_A && ((insn & 0xff) == 0x40)) /* sub.a %sp,const8  */
    pc += 2;
  else if (RIDER_B && ((insn & 0xff) == 0x20)) /* sub.a %sp,const8  */
    pc += 2;
  else
    {
      if ((insn & 0xfffff0ff) == 0xf5b8a089) /* st.a [+%sp]-8,%ax  */
        {
          pc += 4;
          insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));

          if (RIDER_A && ((insn & 0xf0ff) == 0xa080)) /* mov.aa %an,%sp  */
            {
              pc += 2;
              insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
            }
          else if (RIDER_B && ((insn & 0xf0ff) == 0xa040)) /* mov.aa %an,%sp  */
            {
              pc += 2;
              insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
            }
          else if ((insn & 0x0fffffff) == 0x0000a001) /* mov.aa %an,%sp  */
            {
              pc += 4;
              insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
            }
        }

      if (RIDER_A && ((insn & 0xff) == 0x40)) /* sub.a %sp,const8  */
        pc += 2;
      else if (RIDER_B && ((insn & 0xff) == 0x20)) /* sub.a %sp,const8  */
        pc += 2;
      else if ((insn & 0xffff) == 0xaad9) /* lea %sp,[%sp]const16  */
        pc += 4;
      else if ((insn & 0xf0000fff) == 0xf0000091) /* movh.a %a15,const16  */
        {
          CORE_ADDR old_pc = pc;

          pc += 4;
          insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
          if ((insn & 0x0000ffff) == 0x0000ffd9) /* lea %a15,[%a15]const16  */
            {
              pc += 4;
              insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
            }
          if (insn == 0xa020fa01) /* sub.a %sp,%sp,%a15  */
            pc += 4;
          else
            pc = old_pc;
        }
    }

  /* Handle TOC pointer.  */
  insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
  if ((insn & 0xf0000fff) == 0xc0000091)
    {
      pc += 8;
      if (main_pc != (CORE_ADDR) 0)
        insn = read_memory_integer (pc, 4, gdbarch_byte_order (gdbarch));
    }

  /* Check for "call __main".  TODO: Should also check for CALLA etc.  */
  if (main_pc != (CORE_ADDR) 0)
    {
      if ((insn & 0x000000ff) == 0x0000006d)
        {
          offset = (insn & 0xffff0000) >> 16;
          offset |= (insn & 0x0000ff00) << 8;
          if (offset & 0x800000)
            offset |= ~0xffffff;
          offset <<= 1;
          if ((pc + offset) == __main_pc)
            pc += 4;
        }
      else if (RIDER_B && ((insn & 0xff) == 0x5c))
        {
          offset = (insn & 0x0000ff00) >> 8;
          if (offset & 0x80)
            offset |= ~0xff;
          offset <<= 1;
          if ((pc + offset) == __main_pc)
            pc += 2;
        }
    }

  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "0x%08lx\n", pc);

  return pc;
#endif
}

static const char * tricore_regnr2str(int i)
{
if (i==TRICORE_D0_REGNUM) return "D0";
if (i==TRICORE_D1_REGNUM) return "D1";
if (i==TRICORE_D2_REGNUM) return "D2";
if (i==TRICORE_D3_REGNUM) return "D3";
if (i==TRICORE_D4_REGNUM) return "D4";
if (i==TRICORE_DARG0_REGNUM) return "D4";
if (i==TRICORE_D5_REGNUM) return "D5";
if (i==TRICORE_D6_REGNUM) return "D6";
if (i==TRICORE_D7_REGNUM) return "D7";
if (i==TRICORE_DARGLAST_REGNUM) return "D7";
if (i==TRICORE_D8_REGNUM) return "D8";
if (i==TRICORE_D9_REGNUM) return "D9";
if (i==TRICORE_D10_REGNUM) return "D10";
if (i==TRICORE_D11_REGNUM) return "D11";
if (i==TRICORE_D12_REGNUM) return "D12";
if (i==TRICORE_D13_REGNUM) return "D13";
if (i==TRICORE_D14_REGNUM) return "D14";
if (i==TRICORE_D15_REGNUM) return "D15";
if (i==TRICORE_A0_REGNUM) return "A0";
if (i==TRICORE_A1_REGNUM) return "A1";
if (i==TRICORE_A2_REGNUM) return "A2";
if (i==TRICORE_A3_REGNUM) return "A3";
if (i==TRICORE_A4_REGNUM) return "A4";
if (i==TRICORE_STRUCT_RETURN_REGNUM) return "A4";
if (i==TRICORE_AARG0_REGNUM) return "A4";
if (i==TRICORE_A5_REGNUM) return "A5";
if (i==TRICORE_A6_REGNUM) return "A6";
if (i==TRICORE_A7_REGNUM) return "A7";
if (i==TRICORE_AARGLAST_REGNUM) return "A7";
if (i==TRICORE_A8_REGNUM) return "A8";
if (i==TRICORE_A9_REGNUM) return "A9";
if (i==TRICORE_A10_REGNUM) return "A10";
if (i==TRICORE_SP_REGNUM) return "SP_A10";
if (i==TRICORE_FP_REGNUM) return "FP_A10";
if (i==TRICORE_A11_REGNUM) return "A11";
if (i==TRICORE_RA_REGNUM) return "A11";
if (i==TRICORE_A12_REGNUM) return "A12";
if (i==TRICORE_A13_REGNUM) return "A13";
if (i==TRICORE_A14_REGNUM) return "A14";
if (i==TRICORE_A15_REGNUM) return "A15";
if (i==TRICORE_LCX_REGNUM) return "LCX";
if (i==TRICORE_FCX_REGNUM) return "FCX";
if (i==TRICORE_PCXI_REGNUM) return "PCXI";
if (i==TRICORE_PSW_REGNUM) return "PSW";
if (i==TRICORE_PC_REGNUM) return "PC";
if (i==TRICORE_ICR_REGNUM) return "ICR";
if (i==TRICORE_ISP_REGNUM) return "ISP";
if (i==TRICORE_BTV_REGNUM) return "BTV";
if (i==TRICORE_BIV_REGNUM) return "BIV";
if (i==TRICORE_SYSCON_REGNUM) return "SYSCON";
if (i==TRICORE_PMUCON0_REGNUM) return "PMUCON0";
if (i==TRICORE_DMUCON_REGNUM) return "DMUCON";
return NULL;
};

static struct tricore_frame_cache *
tricore_alloc_frame_cache (struct frame_info *this_frame)
{
  struct tricore_frame_cache *cache;

  cache = FRAME_OBSTACK_ZALLOC (struct tricore_frame_cache);
  cache->saved_regs = trad_frame_alloc_saved_regs (this_frame);

  /* Base address.  */
  cache->base = 0;
  cache->pc = 0;
  return cache;
}

static struct tricore_frame_cache *
tricore_frame_unwind_cache (struct frame_info *this_frame, void **this_cache)
{
  struct tricore_frame_cache *cache;
  struct gdbarch *gdbarch = get_frame_arch (this_frame);

  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  CORE_ADDR current_pc;
  int i;
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache *this_cache %lx \n",(unsigned long ) (*this_cache));
  if (*this_cache)
  {
      cache=(struct tricore_frame_cache *) *this_cache;
      if (tricore_debug>1)
        {
      for (i=0; i<TRICORE_NUM_REGS; i+=1)
        {
          fprintf_unfiltered (gdb_stdlog,"%d %s",i,tricore_regnr2str(i));
          fprintf_unfiltered (gdb_stdlog,"%lx ",cache->frame_regs[i]);
          fprintf_unfiltered (gdb_stdlog,"%lx ",cache->saved_regs[i].realreg);
          fprintf_unfiltered (gdb_stdlog,"%lx \n",cache->saved_regs[i].addr);
        }
        }
      return cache;
  }
  cache = tricore_alloc_frame_cache (this_frame);
  *this_cache = cache;
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache *this_cache alloc %lx \n",(unsigned long ) (*this_cache));
  /* In principle, for normal frames, fp holds the frame pointer,
     which holds the base address for the current stack frame.
     However, for functions that don't need it, the frame pointer is
     optional.  For these "frameless" functions the frame pointer is
     actually the frame pointer of the calling frame.  */

  cache->pc = get_frame_func (this_frame);
  cache->frame_func=get_frame_func (this_frame);;
  current_pc = get_frame_pc (this_frame);
  for (i=0; i<TRICORE_NUM_REGS; i+=1)
    {
      cache->frame_regs[i]=get_frame_register_unsigned (this_frame, i);
    }
  if (tricore_debug)
    {
    fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache level=%d get_frame_func()=%8.8lx get_frame_pc()=%8.8lx\n",frame_relative_level (this_frame),cache->pc,current_pc);
    fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache pc=%8.8lx \n",cache->frame_regs[TRICORE_PC_REGNUM]);
    fprintf_unfiltered (gdb_stdlog,"a11=%8.8lx ",cache->frame_regs[TRICORE_A11_REGNUM]);
    fprintf_unfiltered (gdb_stdlog,"pcxi=%8.8lx ",cache->frame_regs[TRICORE_PCXI_REGNUM]);
    fprintf_unfiltered (gdb_stdlog,"a10=%8.8lx \n",cache->frame_regs[TRICORE_A10_REGNUM]);
    }
  //depending on the values we have to decide what to do and how to populate the saved registers
  //A11 can be zero, indicating that no callee pc is know
  //PCXI can be zero, PCXI can be valid upper and lower context
  //A10 can be zero
  //PC can be zero
  //we always want to deliver a valid stack, but in addition unwinding information, if undwinding should continue
  //the level can be also 0, the innermost or higher

  //focus on A11 and PCXI
  //if A11==0 and PCXI!=0, do not further proceed, but set register values
  //see also tricore_frame_status_sniffer
  cache->unwind_reason=UNWIND_NO_REASON;
  if ((cache->frame_regs[TRICORE_A11_REGNUM]==cache->frame_regs[TRICORE_PC_REGNUM]) && (cache->frame_regs[TRICORE_PCXI_REGNUM]==0) && (cache->frame_regs[TRICORE_SP_REGNUM]==0))
    {
      trad_frame_set_value (cache->saved_regs, TRICORE_PC_REGNUM, cache->frame_regs[TRICORE_A11_REGNUM]); //set PC to A11
      trad_frame_set_value (cache->saved_regs, TRICORE_SP_REGNUM, cache->frame_regs[TRICORE_SP_REGNUM]);
      trad_frame_set_value (cache->saved_regs, TRICORE_PCXI_REGNUM, cache->frame_regs[TRICORE_PCXI_REGNUM]);
      if (tricore_debug)
          {
          fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache UNWIND_OUTERMOST Case 0\n");
          }
      cache->unwind_reason=UNWIND_OUTERMOST;
      //we should stop unwinding
      return cache;
    }
  if ((cache->frame_regs[TRICORE_A11_REGNUM]==0) && (cache->frame_regs[TRICORE_PCXI_REGNUM]!=0))
    {
      trad_frame_set_value (cache->saved_regs, TRICORE_PC_REGNUM, cache->frame_regs[TRICORE_A11_REGNUM]); //set PC to A11
      trad_frame_set_value (cache->saved_regs, TRICORE_SP_REGNUM, cache->frame_regs[TRICORE_SP_REGNUM]);
      trad_frame_set_value (cache->saved_regs, TRICORE_PCXI_REGNUM, cache->frame_regs[TRICORE_PCXI_REGNUM]);
      if (tricore_debug)
          {
          fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache UNWIND_OUTERMOST Case 1\n");
          }
      cache->unwind_reason=UNWIND_OUTERMOST;
      //we should stop unwinding
      return cache;
    }
  if ((cache->frame_regs[TRICORE_A11_REGNUM]==0) && (cache->frame_regs[TRICORE_PCXI_REGNUM]==0))
    {
      trad_frame_set_value (cache->saved_regs, TRICORE_PC_REGNUM, cache->frame_regs[TRICORE_A11_REGNUM]); //set PC to A11
      trad_frame_set_value (cache->saved_regs, TRICORE_SP_REGNUM, cache->frame_regs[TRICORE_SP_REGNUM]);
      trad_frame_set_value (cache->saved_regs, TRICORE_PCXI_REGNUM, cache->frame_regs[TRICORE_PCXI_REGNUM]);
      //we should stop unwinding
      if (tricore_debug)
          {
          fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache UNWIND_OUTERMOST Case 2\n");
          }
      cache->unwind_reason=UNWIND_OUTERMOST;
      return cache;
    }
  if ((cache->frame_regs[TRICORE_A11_REGNUM]==cache->frame_regs[TRICORE_PC_REGNUM]) && (cache->frame_regs[TRICORE_PC_REGNUM]!=0) && (cache->frame_regs[TRICORE_PCXI_REGNUM]==0))
    {
      trad_frame_set_value (cache->saved_regs, TRICORE_PC_REGNUM, cache->frame_regs[TRICORE_A11_REGNUM]); //set PC to A11
      trad_frame_set_value (cache->saved_regs, TRICORE_SP_REGNUM, cache->frame_regs[TRICORE_SP_REGNUM]);
      trad_frame_set_value (cache->saved_regs, TRICORE_PCXI_REGNUM, cache->frame_regs[TRICORE_PCXI_REGNUM]);
      //we should stop unwinding
      if (tricore_debug)
          {
          fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache UNWIND_OUTERMOST Case 3\n");
          }
      cache->unwind_reason=UNWIND_OUTERMOST;
      return cache;
    }
  if ((cache->frame_regs[TRICORE_A11_REGNUM]!=cache->frame_regs[TRICORE_PC_REGNUM]) && (cache->frame_regs[TRICORE_A11_REGNUM]!=0) && (cache->frame_regs[TRICORE_PC_REGNUM]!=0) && (cache->frame_regs[TRICORE_PCXI_REGNUM]==0))
    {
      trad_frame_set_value (cache->saved_regs, TRICORE_A11_REGNUM, 0);
      trad_frame_set_value (cache->saved_regs, TRICORE_PC_REGNUM, cache->frame_regs[TRICORE_A11_REGNUM]); //set PC to A11
      trad_frame_set_value (cache->saved_regs, TRICORE_SP_REGNUM, cache->frame_regs[TRICORE_SP_REGNUM]);
      trad_frame_set_value (cache->saved_regs, TRICORE_PCXI_REGNUM, cache->frame_regs[TRICORE_PCXI_REGNUM]);
      if (tricore_debug)
          {
          fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache UNWIND_OUTERMOST Case 4\n");
          }
//      cache->unwind_reason=UNWIND_OUTERMOST; //can be handled tricore_status_sniffer
      return cache;
    }
  if ((cache->frame_regs[TRICORE_A11_REGNUM]!=0) && (cache->frame_regs[TRICORE_PCXI_REGNUM]!=0) && ((cache->frame_regs[TRICORE_PCXI_REGNUM] & 0x100000)!=0))
    {
      //upper context save, assumption is that it was not jl with valid pcxi
      CORE_ADDR EA_addr;
      EA_addr= ((cache->frame_regs[TRICORE_PCXI_REGNUM] & 0xF0000) << 12) + ((cache->frame_regs[TRICORE_PCXI_REGNUM] & 0xFFFF) << 6);
      gdb_byte buf[16*4]; //16 registers from csa
      uint32_t  *pcsa;
      pcsa=(uint32_t *) &buf[0];

      read_memory (EA_addr, buf, 16*4);
      trad_frame_set_value (cache->saved_regs, TRICORE_PCXI_REGNUM,pcsa[0]);
      trad_frame_set_value (cache->saved_regs, TRICORE_PSW_REGNUM,pcsa[1]);
        trad_frame_set_value (cache->saved_regs, TRICORE_A10_REGNUM,pcsa[2]);
        trad_frame_set_value (cache->saved_regs, TRICORE_A11_REGNUM,pcsa[3]);
        trad_frame_set_value (cache->saved_regs, TRICORE_D8_REGNUM,pcsa[4]);
        trad_frame_set_value (cache->saved_regs, TRICORE_D9_REGNUM,pcsa[5]);
        trad_frame_set_value (cache->saved_regs, TRICORE_D10_REGNUM,pcsa[6]);
        trad_frame_set_value (cache->saved_regs, TRICORE_D11_REGNUM,pcsa[7]);
        trad_frame_set_value (cache->saved_regs, TRICORE_A12_REGNUM,pcsa[8]);
        trad_frame_set_value (cache->saved_regs, TRICORE_A13_REGNUM,pcsa[9]);
        trad_frame_set_value (cache->saved_regs, TRICORE_A14_REGNUM,pcsa[10]);
        trad_frame_set_value (cache->saved_regs, TRICORE_A15_REGNUM,pcsa[11]);
        trad_frame_set_value (cache->saved_regs, TRICORE_D12_REGNUM,pcsa[12]);
        trad_frame_set_value (cache->saved_regs, TRICORE_D13_REGNUM,pcsa[13]);
        trad_frame_set_value (cache->saved_regs, TRICORE_D14_REGNUM,pcsa[14]);
        trad_frame_set_value (cache->saved_regs, TRICORE_D15_REGNUM,pcsa[15]);
        trad_frame_set_value (cache->saved_regs, TRICORE_PC_REGNUM, cache->frame_regs[TRICORE_A11_REGNUM]); //set PC to A11
        if (tricore_debug>1)
          {
        for (i=0; i<TRICORE_NUM_REGS; i+=1)
          {
            fprintf_unfiltered (gdb_stdlog,"Upper %d %s",i,tricore_regnr2str(i));
            fprintf_unfiltered (gdb_stdlog,"%lx ",cache->frame_regs[i]);
            fprintf_unfiltered (gdb_stdlog,"%lx ",cache->saved_regs[i].realreg);
            fprintf_unfiltered (gdb_stdlog,"%lx \n",cache->saved_regs[i].addr);
          }
          }
      return cache;
    }
  //TODO optimize it
  if ((cache->frame_regs[TRICORE_A11_REGNUM]!=0) && (cache->frame_regs[TRICORE_PCXI_REGNUM]!=0) && ((cache->frame_regs[TRICORE_PCXI_REGNUM] & 0x100000)==0))
    {
      //lower context save, assumption is that it was not jl with valid pcxi
      CORE_ADDR EA_addr;
      CORE_ADDR mem;
      CORE_ADDR new_upper_pcxi;
      CORE_ADDR new_upper_pc;
      //TODO optimize
      EA_addr= ((cache->frame_regs[TRICORE_PCXI_REGNUM] & 0xF0000) << 12) + ((cache->frame_regs[TRICORE_PCXI_REGNUM] & 0xFFFF) << 6);
      mem = read_memory_unsigned_integer (EA_addr, 4,byte_order); //PCXI
      //TODO check if really new upper
      new_upper_pcxi=mem;
      mem = read_memory_unsigned_integer (EA_addr+4, 4,byte_order); //A11
      new_upper_pc=mem;
      mem = read_memory_unsigned_integer (EA_addr+8, 4,byte_order); //A2
      trad_frame_set_value (cache->saved_regs, TRICORE_A2_REGNUM, mem);
      mem = read_memory_unsigned_integer (EA_addr+12, 4,byte_order); //A3
      trad_frame_set_value (cache->saved_regs, TRICORE_A3_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+16, 4,byte_order); //D0
      trad_frame_set_value (cache->saved_regs, TRICORE_D0_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+20, 4,byte_order); //D1
      trad_frame_set_value (cache->saved_regs, TRICORE_D1_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+24, 4,byte_order); //D2
      trad_frame_set_value (cache->saved_regs, TRICORE_D2_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+28, 4,byte_order); //D3
      trad_frame_set_value (cache->saved_regs, TRICORE_D3_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+32, 4,byte_order); //A4
      trad_frame_set_value (cache->saved_regs, TRICORE_A4_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+36, 4,byte_order); //A5
      trad_frame_set_value (cache->saved_regs, TRICORE_A5_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+40, 4,byte_order); //A6
      trad_frame_set_value (cache->saved_regs, TRICORE_A6_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+44, 4,byte_order); //A7
      trad_frame_set_value (cache->saved_regs, TRICORE_A7_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+48, 4,byte_order); //D4
      trad_frame_set_value (cache->saved_regs, TRICORE_D4_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+52, 4,byte_order); //D5
      trad_frame_set_value (cache->saved_regs, TRICORE_D5_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+56, 4,byte_order); //D6
      trad_frame_set_value (cache->saved_regs, TRICORE_D6_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+60, 4,byte_order); //D7
      trad_frame_set_value (cache->saved_regs, TRICORE_D7_REGNUM,mem);
      EA_addr= ((new_upper_pcxi & 0xF0000) << 12) + ((new_upper_pcxi & 0xFFFF) << 6);
      mem = read_memory_unsigned_integer (EA_addr, 4,byte_order); //PCXI the prev PCXI
      trad_frame_set_value (cache->saved_regs, TRICORE_PCXI_REGNUM,mem);
      mem = read_memory_unsigned_integer (EA_addr+4, 4,byte_order); //PSW
        trad_frame_set_value (cache->saved_regs, TRICORE_PSW_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+8, 4,byte_order); //A10
        trad_frame_set_value (cache->saved_regs, TRICORE_A10_REGNUM, mem);
        mem = read_memory_unsigned_integer (EA_addr+12, 4,byte_order); //A11
        trad_frame_set_value (cache->saved_regs, TRICORE_A11_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+16, 4,byte_order); //D8
        trad_frame_set_value (cache->saved_regs, TRICORE_D8_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+20, 4,byte_order); //D9
        trad_frame_set_value (cache->saved_regs, TRICORE_D9_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+24, 4,byte_order); //D10
        trad_frame_set_value (cache->saved_regs, TRICORE_D10_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+28, 4,byte_order); //D11
        trad_frame_set_value (cache->saved_regs, TRICORE_D11_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+32, 4,byte_order); //A12
        trad_frame_set_value (cache->saved_regs, TRICORE_A12_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+36, 4,byte_order); //A13
        trad_frame_set_value (cache->saved_regs, TRICORE_A13_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+40, 4,byte_order); //A14
        trad_frame_set_value (cache->saved_regs, TRICORE_A14_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+44, 4,byte_order); //A15
        trad_frame_set_value (cache->saved_regs, TRICORE_A15_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+48, 4,byte_order); //D12
        trad_frame_set_value (cache->saved_regs, TRICORE_D12_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+52, 4,byte_order); //D13
        trad_frame_set_value (cache->saved_regs, TRICORE_D13_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+56, 4,byte_order); //D14
        trad_frame_set_value (cache->saved_regs, TRICORE_D14_REGNUM,mem);
        mem = read_memory_unsigned_integer (EA_addr+60, 4,byte_order); //D15
        trad_frame_set_value (cache->saved_regs, TRICORE_D15_REGNUM,mem);
        trad_frame_set_value (cache->saved_regs, TRICORE_PC_REGNUM, new_upper_pc); //set PC to A11 of upper context
        if (tricore_debug)
          {
        for (i = 0; i < TRICORE_NUM_REGS; i++)
          {
            if ((i==TRICORE_SP_REGNUM) || (i==TRICORE_PC_REGNUM) || (i==TRICORE_A11_REGNUM) || (i==TRICORE_A10_REGNUM) || (i==TRICORE_PCXI_REGNUM) || (i==TRICORE_D4_REGNUM) || (i==TRICORE_A15_REGNUM))
              fprintf_unfiltered (gdb_stdlog,"frame %lx ->saved_regs[%s].realreg=%x .addr=0x%lx\n",cache->frame_regs[i],tricore_regnr2str(i),cache->saved_regs[i].realreg,cache->saved_regs[i].addr);
          }
          }
        return cache;
    }
  if (tricore_debug)
     {
     fprintf_unfiltered (gdb_stdlog,"***tricore_frame_unwind_cache should not be here level=%d cache_pc=%lx current_pc=%lx\n",frame_relative_level (this_frame),cache->pc,current_pc);
     }
  cache->unwind_reason=UNWIND_OUTERMOST;
        return cache;
}

static enum unwind_stop_reason
tricore_frame_default_unwind_stop_reason (struct frame_info *this_frame,
                                       void **this_cache)
{
  struct tricore_frame_cache *cache;
  CORE_ADDR maddr;
  struct bound_minimal_symbol msym;
  cache=(struct tricore_frame_cache *) *this_cache;

  if (tricore_debug)
    {
      fprintf_unfiltered (gdb_stdlog, "***tricore_frame_default_unwind_stop_reason %d\n",frame_relative_level (this_frame));
    }

  //TODO introduce switch for bt stop after corex[0....x]_main .....
  msym = lookup_minimal_symbol_text ("core0_main",(struct objfile *) 0);
  if (msym.minsym != NULL)
    {
      maddr = gdbarch_convert_from_func_ptr_addr (get_frame_arch (this_frame),BMSYMBOL_VALUE_ADDRESS (msym),current_top_target ());
      fprintf_unfiltered (gdb_stdlog, "***tricore_frame_default_unwind_stop_reason btlimit %d maddr=%lx frame_func=%lx\n",frame_relative_level (this_frame),maddr,cache->frame_func);
      if (cache->frame_func==maddr) return UNWIND_OUTERMOST;
    }
  return cache->unwind_reason;
}


static void
tricore_frame_default_this_id (struct frame_info *this_frame, void **this_cache,
                    struct frame_id *this_id)
{
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_default_this_id \n");
  struct tricore_frame_cache *cache = tricore_frame_unwind_cache (this_frame, this_cache);

  if (tricore_debug)
    {
      fprintf_unfiltered (gdb_stdlog, "***tricore_frame_default_this_id build level=%d \n",frame_relative_level(this_frame));
      fprintf_unfiltered (gdb_stdlog, "frame pc=%lx ",cache->frame_regs[TRICORE_PC_REGNUM]);
      fprintf_unfiltered (gdb_stdlog, "saved pc=%lx ",cache->saved_regs[TRICORE_PC_REGNUM].addr);
      fprintf_unfiltered (gdb_stdlog, "frame a11=%lx ",cache->frame_regs[TRICORE_A11_REGNUM]);
      fprintf_unfiltered (gdb_stdlog, "saved a11=%lx ",cache->saved_regs[TRICORE_A11_REGNUM].addr);
      fprintf_unfiltered (gdb_stdlog, "frame pcxi=%lx ",cache->frame_regs[TRICORE_PCXI_REGNUM]);
      fprintf_unfiltered (gdb_stdlog, "saved pcxi=%lx ",cache->saved_regs[TRICORE_PCXI_REGNUM].addr);
      fprintf_unfiltered (gdb_stdlog, "frame a10=%lx ",cache->frame_regs[TRICORE_SP_REGNUM]);
      fprintf_unfiltered (gdb_stdlog, "saved a10=%lx \n",cache->saved_regs[TRICORE_SP_REGNUM].addr);
    }

  *this_id = frame_id_build_special (cache->saved_regs[TRICORE_SP_REGNUM].addr, cache->saved_regs[TRICORE_PC_REGNUM].addr, cache->saved_regs[TRICORE_PCXI_REGNUM].addr);
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_default_this_id end\n");
}

static struct value *
tricore_frame_default_prev_register (struct frame_info *this_frame,
                          void **prologue_cache, int regnum)
{
  struct value *result;
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_default_prev_register %d\n",regnum);
  struct tricore_frame_cache *info = tricore_frame_unwind_cache (this_frame,
                                                    prologue_cache);
  result= trad_frame_get_prev_register (this_frame, info->saved_regs, regnum);
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_default_prev_register end \n");
  return result;
}

static int tricore_frame_default_sniffer (const struct frame_unwind *self,
                       struct frame_info *this_frame,
                       void **this_prologue_cache)
{
  if (tricore_debug)
    {
    fprintf_unfiltered (gdb_stdlog, "***tricore_frame_default_sniffer ");
    }
//TODO when tricore default frame sniffer can not be used

return 1;
}

static const struct frame_unwind tricore_frame_default_unwind = {
  NORMAL_FRAME,
  tricore_frame_default_unwind_stop_reason,
  tricore_frame_default_this_id,
  tricore_frame_default_prev_register,
  NULL,
  tricore_frame_default_sniffer,
  NULL,
  NULL
};

static enum unwind_stop_reason
tricore_frame_status_unwind_stop_reason (struct frame_info *this_frame,
                                       void **this_cache)
{
  struct tricore_frame_cache *cache;
  cache=(struct tricore_frame_cache *) *this_cache;
  if (tricore_debug)
    {
      fprintf_unfiltered (gdb_stdlog, "***tricore_frame_status_unwind_stop_reason %d\n",frame_relative_level (this_frame));
    }
//TODO exit on corexmain()
//  CORE_ADDR maddr;
//  struct bound_minimal_symbol msym;
//  msym = lookup_minimal_symbol_text ("core0_main",(struct objfile *) 0);
//  if (msym.minsym != NULL)
//    {
//      maddr = gdbarch_convert_from_func_ptr_addr (get_frame_arch (this_frame),BMSYMBOL_VALUE_ADDRESS (msym),current_top_target ());
////      fprintf_unfiltered (gdb_stdlog, "***tricore_frame_status_unwind_stop_reason btlimit %d %8.8lx\n",frame_relative_level (this_frame),maddr);
//      if (cache->frame_func==maddr) return UNWIND_OUTERMOST;
//    }
  return cache->unwind_reason;
}

static void
tricore_frame_status_this_id (struct frame_info *this_frame, void **this_cache,
                    struct frame_id *this_id)
{
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_this_id \n");
  struct tricore_frame_cache *cache = tricore_frame_unwind_cache (this_frame, this_cache);
  if (tricore_debug)
    {
      fprintf_unfiltered (gdb_stdlog, "***tricore_frame_status_this_id  %lx %lx %lx\n",(unsigned long ) (cache),cache->saved_regs[TRICORE_SP_REGNUM].addr,cache->pc);
      fprintf_unfiltered (gdb_stdlog, "***tricore_frame_status_this_id build level=%d \n",frame_relative_level(this_frame));
      fprintf_unfiltered (gdb_stdlog, "frame pc=%lx ",cache->frame_regs[TRICORE_PC_REGNUM]);
      fprintf_unfiltered (gdb_stdlog, "saved pc=%lx ",cache->saved_regs[TRICORE_PC_REGNUM].addr);
      fprintf_unfiltered (gdb_stdlog, "frame a11=%lx ",cache->frame_regs[TRICORE_A11_REGNUM]);
      fprintf_unfiltered (gdb_stdlog, "saved a11=%lx ",cache->saved_regs[TRICORE_A11_REGNUM].addr);
      fprintf_unfiltered (gdb_stdlog, "frame pcxi=%lx ",cache->frame_regs[TRICORE_PCXI_REGNUM]);
      fprintf_unfiltered (gdb_stdlog, "saved pcxi=%lx ",cache->saved_regs[TRICORE_PCXI_REGNUM].addr);
      fprintf_unfiltered (gdb_stdlog, "frame a10=%lx ",cache->frame_regs[TRICORE_SP_REGNUM]);
      fprintf_unfiltered (gdb_stdlog, "saved a10=%lx \n",cache->saved_regs[TRICORE_SP_REGNUM].addr);
   }
  *this_id = frame_id_build_special (cache->saved_regs[TRICORE_SP_REGNUM].addr, cache->saved_regs[TRICORE_PC_REGNUM].addr, cache->saved_regs[TRICORE_PCXI_REGNUM].addr);
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_this_id end\n");
}

static struct value *
tricore_frame_status_prev_register (struct frame_info *this_frame,
                          void **prologue_cache, int regnum)
{
  struct value *result;
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_prev_register \n");
  struct tricore_frame_cache *info = tricore_frame_unwind_cache (this_frame,prologue_cache);
  result= trad_frame_get_prev_register (this_frame, info->saved_regs, regnum);
  if (tricore_debug)   fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_prev_register end \n");
  return result;
}

static int
tricore_frame_status_sniffer (const struct frame_unwind *self,
                       struct frame_info *this_frame,
                       void **this_prologue_cache)
{
  CORE_ADDR reg_a11,reg_pc,reg_a10,reg_pcxi;

  if (tricore_debug)
    {
    fprintf_unfiltered (gdb_stdlog, "***tricore_frame_status_sniffer ");
    }
  //TODO when tricore default frame sniffer can not be used
  reg_pc=get_frame_register_unsigned (this_frame, TRICORE_PC_REGNUM);
  reg_a11=get_frame_register_unsigned (this_frame, TRICORE_A11_REGNUM);
  reg_pcxi=get_frame_register_unsigned (this_frame, TRICORE_PCXI_REGNUM);
  reg_a10=get_frame_register_unsigned (this_frame, TRICORE_A10_REGNUM);

  if (tricore_debug)
    {
    fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer level=%d ",frame_relative_level (this_frame));
    fprintf_unfiltered (gdb_stdlog,"get_frame_func()=%lx ",get_frame_func(this_frame));
    fprintf_unfiltered (gdb_stdlog,"get_frame_pc()=%lx\n",get_frame_pc(this_frame));
    fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer pc=%8.8lx \n",reg_pc);
    fprintf_unfiltered (gdb_stdlog,"a11=%8.8lx ",reg_a11);
    fprintf_unfiltered (gdb_stdlog,"pcxi=%8.8lx ",reg_pcxi);
    fprintf_unfiltered (gdb_stdlog,"a10=%8.8lx \n",reg_a10);
    }
  //decide now if we take this sniffer, for frames which dwarf can not handle correctly
  //see also tricore_frame_unwind_cache
  if ((reg_a11==reg_pc) && (reg_pcxi==0) && (reg_a10==0))
     {
       if (tricore_debug)
           {
           fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer take Case 0\n");
           }
       //do not pass to dwarf2 unwinders
       return 1;
     }
   if ((reg_a11==0) && (reg_pcxi!=0))
     {
       if (tricore_debug)
           {
           fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer take Case 1\n");
           }
       //do not pass to dwarf2 unwinders
       return 1;
     }
   if ((reg_a11==0) && (reg_pcxi==0))
     {
       if (tricore_debug)
           {
           fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer take Case 2\n");
           }
       //do not pass to dwarf2 unwinders
       return 1;
     }
   if ((reg_a11==reg_pc) && (reg_pc!=0) && (reg_pcxi==0))
     {
       if (tricore_debug)
           {
           fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer take Case 3\n");
           }
       //do not pass to dwarf2 unwinders
       return 1;
     }
   if ((reg_a11!=reg_pc) && (reg_a11!=0) && (reg_pc!=0) && (reg_pcxi==0))
     {
       if (tricore_debug)
           {
           fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer take Case 4\n");
           }
       //do not pass to dwarf2 unwinders
       return 1;
     }
   if ((reg_a11!=0) && (reg_pc!=0) && ((reg_pcxi & 0x100000)!=0))
     {
       if (tricore_debug)
           {
           fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer upper context do not take 5\n");
           }
       // pass to dwarf2 unwinders
       return 0;
     }
   if ((reg_a11!=0) && (reg_pc!=0) && ((reg_pcxi & 0x100000)==0))
     {
       if (tricore_debug)
           {
           fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer lower context take 6\n");
           }
       // pass not to dwarf2 unwinders
       return 1;
     }
   if (tricore_debug)
      {
      fprintf_unfiltered (gdb_stdlog,"***tricore_frame_status_sniffer should not be here\n");
      }
//take it
return 1;
}

static const struct frame_unwind tricore_frame_status_unwind = {
  NORMAL_FRAME,
  tricore_frame_status_unwind_stop_reason,
  tricore_frame_status_this_id,
  tricore_frame_status_prev_register,
  NULL,
  tricore_frame_status_sniffer,
  NULL,
  NULL
};

/* Return number of args passed to a frame.
   Can return -1, meaning no way to tell. */

static int
tricore_frame_num_args (struct frame_info *fi)
{
#if 0 /* WT 2006-04-19 */
  return -1;
#else
  return 0;
#endif /* WT 2006-04-19 */
}

/* TriCore uses CSAs (Context Save Area) in a linked list.
   The normal stack concept cannot be used for TriCore. */
static int
tricore_inner_than (CORE_ADDR lhs, CORE_ADDR rhs)
{
  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "*** tricore_inner_than: lhs=0x%08lx, rhs=0x%08lx\n", lhs, rhs);
  return 0;
}

/* Write the return value in SRC with type TYPE into the
   appropriate register(s).  This is called when making the
   current frame returning using "ret value_to_be_returned".  */

static void
tricore_store_return_value (struct type *type, struct regcache *regcache,
                         const gdb_byte *valbuf)
{
  struct gdbarch *gdbarch = regcache->arch ();
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int len = TYPE_LENGTH (type);
  int regno;
//it should never arrive here with code_ptr....
  if ((type->code() == TYPE_CODE_PTR) ||
      (type->code() == TYPE_CODE_REF))
    regno = TRICORE_A2_REGNUM;
  else
    regno = TRICORE_D2_REGNUM;
  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_store_return_value reg=%d len=%d\n",regno,len);
  if (len <= INT_REGISTER_SIZE)
      regcache_cooked_write_unsigned
        (regcache, regno,
         extract_unsigned_integer (valbuf, len, byte_order));
  else if (len <= 2 * INT_REGISTER_SIZE)
    {
      int i, regnum = regno;
      for (i = 0; i < len; i += 4)
        regcache->raw_write (regnum++, valbuf + i);
    }
}

/* Copy the return value in REGS with type TYPE to DST.  This is
   used to find out the return value of a function after a "finish"
   command has been issued, and after a call dummy has returned.  */

static void
tricore_extract_return_value (struct type *type, struct regcache *regcache,
                           gdb_byte *valbuf)
{
  struct gdbarch *gdbarch = regcache->arch ();
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  int len = TYPE_LENGTH (type);

  int regno;
  //it should never arrive here with code_ptr....
  if ((type->code() == TYPE_CODE_PTR) ||
      (type->code() == TYPE_CODE_REF))
    regno = TRICORE_A2_REGNUM;
  else
    regno = TRICORE_D2_REGNUM;

  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_extract_return_value reg=%d len=%d\n",regno,len);
  if (len <= INT_REGISTER_SIZE)
    {
      ULONGEST val;

      regcache_cooked_read_unsigned (regcache, regno, &val);
      store_unsigned_integer (valbuf, len, byte_order, val);
    }
  else if (len <= 2 * INT_REGISTER_SIZE)
    {
      int i, regnum = regno;
      gdb_byte buf[INT_REGISTER_SIZE];
      for (i = 0; len > 0; i += 4, len -= 4)
        {
          regcache->raw_read (regnum++, buf);
          memcpy (valbuf + i, buf, len > 4 ? 4 : len);
        }
    }
}

static int
tricore_type_is_scalar (struct type *t)
{
  return (t->code() != TYPE_CODE_STRUCT
          && t->code() != TYPE_CODE_UNION
          && t->code() != TYPE_CODE_ARRAY);
}

/*
2.2.5 Return Values
2.2.5.1 Scalar Return Values
32-bit return values, other than pointers, are returned in D[2]. This includes all types whose size in memory is less
than 32-bits; they are expanded to 32-bits through zero-extension or sign-extension, according to the type.
64-bit scalar return values are returned in E[2] (register pair D[2]/D[3]).
2.2.5.2 Pointer Return Values
32-bit pointer return values are returned in A[2].
64-bit pointer return values such as circular buffer pointers are returned in the register pair A[2]/A[3].
2.2.5.3 Structure Return Values
Structure return values smaller than 32-bits are returned in D[2] regardless of their field types. Return values up
to 64-bits are returned in the register pair D[2]/D[3] (E[2]) regardless of their field types. This holds true even if all
fields are addresses.
Functions returning structures or unions larger than 64-bits have an implicit first parameter, which is the address
of the caller-allocated storage area for the return value. This first parameter is passed in A[4]. The normal pointer
arguments then start in register A[5] instead of in A[4].
The caller must provide for a buffer of sufficient size. The buffer is typically allocated on the stack to provide reentrancy and to avoid any race conditions where a static buffer may be overwritten.
If a function result is the right-hand side of a structure assignment, the address passed may be that of the left-hand
side, provided that it is not a global object that the called function might access. The called function does not buffer
its writes to the return structure. (i.e. it does not write to a local temporary and perform a copy to the return structure
just prior to returning).
The caller must provide this buffer for large structures even when the caller does not use the return value (for
example, the function was called to achieve a side-effect). The called routine can therefore assume that the buffer
pointer is valid and need not check the pointer value passed in A[4]
*/

static int
tricore_use_struct_convention (struct gdbarch *gdbarch, struct type *type)
{
  int i;
  struct type *fld_type, *tgt_type;
  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_use_struct_convention type=%d len=%ld\n",type->code(),TYPE_LENGTH (type));
  /* 1. The value is greater than 8 bytes -> returned by copying.  */
  if (TYPE_LENGTH (type) > 8)
  {
	  if (tricore_debug)
	    fprintf_unfiltered (gdb_stdlog, "***tricore_use_struct_convention len is greater 8 ret 1\n");
    return 1;
  }
  return 0;
  /* 2. The value is a single basic type -> returned in register.  */
  if (tricore_type_is_scalar (type))
  {
	  if (tricore_debug)
	    fprintf_unfiltered (gdb_stdlog, "***tricore_use_struct_convention is scalar ret 0 \n");
   return 0;
  }
  if (tricore_debug)
  	    fprintf_unfiltered (gdb_stdlog, "***tricore_use_struct_convention more complex \n");
  /* The value is a structure or union with a single element and that
     element is either a single basic type or an array of a single basic
     type whose size is greater than or equal to 4 -> returned in register.  */
  if ((type->code() == TYPE_CODE_STRUCT
       || type->code() == TYPE_CODE_UNION)
       && type->num_fields() == 1)
    {
	  if (tricore_debug)
	  	    fprintf_unfiltered (gdb_stdlog, "***tricore_use_struct_convention struct or union with only one element \n");
	  fld_type = type->field (0).type ();
	  if (tricore_debug)
	  	    fprintf_unfiltered (gdb_stdlog, "***tricore_use_struct_convention 1st element is scalar %d and its size is %d \n",tricore_type_is_scalar (fld_type),TYPE_LENGTH (fld_type));

      if (tricore_type_is_scalar (fld_type) && TYPE_LENGTH (fld_type) >= 4)
      {
        return 0;
      }

      if (fld_type->code() == TYPE_CODE_ARRAY)
        {
          tgt_type = TYPE_TARGET_TYPE (fld_type);
          if (tricore_type_is_scalar (tgt_type) && TYPE_LENGTH (tgt_type) >= 4)
            return 0;
        }
    }

  /* The value is a structure whose first element is an integer or a float,
     and which contains no arrays of more than two elements -> returned in
     register.  */
  if (type->code() == TYPE_CODE_STRUCT
      && tricore_type_is_scalar ( type->field (0).type ())
      && TYPE_LENGTH ( type->field (0).type ()) == 4)
    {
      for (i = 1; i < type->num_fields(); ++i)
        {
          fld_type =  type->field (0).type ();
          if (fld_type->code() == TYPE_CODE_ARRAY)
            {
              tgt_type = TYPE_TARGET_TYPE (fld_type);
              if (TYPE_LENGTH (tgt_type) > 0
                  && TYPE_LENGTH (fld_type) / TYPE_LENGTH (tgt_type) > 2)
                return 1;
            }
        }
      return 0;
    }

  /* The value is a union which contains at least one field which
     would be returned in registers according to these rules ->
     returned in register.  */
  if (type->code() == TYPE_CODE_UNION)
    {
      for (i = 0; i < type->num_fields(); ++i)
        {
          fld_type =  type->field (0).type ();
          if (!tricore_use_struct_convention (gdbarch, fld_type))
            return 0;
        }
    }
  if (tricore_debug)
  	    fprintf_unfiltered (gdb_stdlog, "***tricore_use_struct_convention no criteria matched, assumption is mem \n");

  return 1;
}

/* Setting/getting return values from functions.

   If USE_STRUCT_CONVENTION returns 0, then gdb uses STORE_RETURN_VALUE
   and EXTRACT_RETURN_VALUE to store/fetch the functions return value. */

/* Will a function return an aggregate type in memory or in a
   register?  Return 0 if an aggregate type can be returned in a
   register, 1 if it must be returned in memory.  */

static enum return_value_convention
tricore_return_value (struct gdbarch *gdbarch, struct value *functype,
                   struct type *valtype, struct regcache *regcache,
                   gdb_byte *readbuf, const gdb_byte *writebuf)
{
  if (tricore_use_struct_convention (gdbarch, valtype))
    return RETURN_VALUE_STRUCT_CONVENTION;
  if (writebuf)
    tricore_store_return_value (valtype, regcache, writebuf);
  else if (readbuf)
    tricore_extract_return_value (valtype, regcache, readbuf);
  return RETURN_VALUE_REGISTER_CONVENTION;
}


/* Figure out where the longjmp will land.  We expect the first arg (%a4)
   to be a pointer to the jmp_buf structure from which we extract the PC
   that we will land at.  The PC is copied into *PC.  This routine returns
   true on success.  */

static int
tricore_get_longjmp_target (struct frame_info *frame, CORE_ADDR *pc)
{
  CORE_ADDR a4;
  CORE_ADDR a2;
  struct gdbarch *gdbarch = get_frame_arch (frame);
  a4 = get_frame_register_unsigned(frame, TRICORE_A4_REGNUM);

  *pc = read_memory_integer (a4, 4, gdbarch_byte_order (gdbarch));
  a2 = read_memory_integer (a4+8, 4, gdbarch_byte_order (gdbarch));
  if (tricore_debug)
	  debug_printf ("***tricore_get_longjmp_target pc=%8.8x jia2=%8.8x\n",*pc,a2);
  *pc=a2;
	  return 1;
}

/* Caveat: Writing to TriCore's scratch pad RAM (SPRAM) is only allowed
   in chunks of 32 bits and only at 32-bit-aligned addresses.  Since a
   breakpoint instruction ("debug") only takes 16 bits, we need to be
   careful when inserting/removing breakpoints.  */

//not used
static int
tricore_memory_insert_breakpoint (struct gdbarch *gdbarch, struct bp_target_info *bp_tgt)
{
  CORE_ADDR addr = bp_tgt->placed_address = bp_tgt->reqstd_address;
  int val, offs;
  gdb_byte bp[] = TRICORE_BREAKPOINT;
  gdb_byte contents_cache[4];

  /* Save the memory contents.  */
  val = target_read_memory (addr & ~3, contents_cache, 4);
  if (val != 0)
    return val;			/* return error */

  memcpy (bp_tgt->shadow_contents, contents_cache, 4);
  bp_tgt->shadow_len = 4;


  /* Write the breakpoint.  */
  /* check word alignment */
  offs = ((addr & 3) ? 2 : 0);
  memcpy(contents_cache + offs, bp, 2);
  val = target_write_memory (addr & ~3, contents_cache, 4);

  return val;
}

//not used
static int
tricore_memory_remove_breakpoint (struct gdbarch *gdbarch,
			       struct bp_target_info *bp_tgt)
{
  CORE_ADDR addr = bp_tgt->placed_address;
  gdb_byte *contents_cache = bp_tgt->shadow_contents;
  gdb_byte mem_cache[4];
  int val, offs;

  val = target_read_memory (addr & ~3, mem_cache, 4);
  if (val != 0)
    return val;			/* return error */
  
  offs = ((addr & 3) ? 2 : 0);
  memcpy(mem_cache + offs, contents_cache + offs , 2);  

  val = target_write_memory (addr & ~3, mem_cache, 4);

  return val;
}

static const unsigned char *
tricore_breakpoint_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr, int *lenptr)
{
  static const unsigned char breakpoint_insn[] = TRICORE_BREAKPOINT;

  *lenptr = sizeof (breakpoint_insn);
  return breakpoint_insn;
}
//TODO Dwarf2 for tricore needs a detailed analysis
//hooks in gcc and gdb, maybe compare to others
static struct value *tricore_dwarf2_prev_register (struct frame_info *this_frame,
                              void **this_cache, int regnum)
{
  struct gdbarch *gdbarch = get_frame_arch (this_frame);
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  ULONGEST value;
  ULONGEST pcxi=0,pcxi_addr=0;
  struct value *result;

  if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register level=%d rnr=%d \n",frame_relative_level (this_frame),regnum);
  switch (regnum)
    {
    case TRICORE_PC_REGNUM:
//      if (frame_relative_level (this_frame)==0)
//      {
//    	  value=get_frame_register_unsigned (this_frame, TRICORE_PC_REGNUM);
//    	  result=frame_unwind_got_constant (this_frame,regnum,value);
//    	  return result;
//      }
   	    value=get_frame_register_unsigned (this_frame, TRICORE_A11_REGNUM);
    	result=frame_unwind_got_constant (this_frame,regnum,value);
        if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result PC from A11 lval %d %8.8lx\n",value_lval_const(result),value);
//
//    	result=frame_unwind_got_register (this_frame, regnum,TRICORE_A11_REGNUM);
//      if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result PC lval %d\n",value_lval_const(result));
      return result;
    case TRICORE_A14_REGNUM:
      {
        gdb_byte buf[4];
        memset (&buf[0], 0, 4);
        pcxi = get_frame_register_unsigned (this_frame, TRICORE_PCXI_REGNUM);
        if (pcxi!=0)
          {
          pcxi_addr= ((pcxi & 0xF0000) << 12) + ((pcxi & 0xFFFF) << 6);
          }
        else
          {
          }
        result=frame_unwind_got_memory (this_frame, regnum,pcxi_addr+40);
        if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result A14 from PCXI lval %d\n",value_lval_const(result));
        return result;
      }
    case TRICORE_A11_REGNUM:
      {
    	gdb_byte buf[4];
        memset (&buf[0], 0, 4);
        pcxi = get_frame_register_unsigned (this_frame, TRICORE_PCXI_REGNUM);
        if (pcxi!=0)
          {
          pcxi_addr= ((pcxi & 0xF0000) << 12) + ((pcxi & 0xFFFF) << 6);
          }
        else
          {
          }
        result=frame_unwind_got_memory (this_frame, regnum,pcxi_addr+12);
        return result;
//        value=read_memory_unsigned_integer (pcxi_addr+12, 4,byte_order); //PCXI
//
//        if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result A11 via PCXI lval %d %8.8lx\n",value_lval_const(result),value);
//
//    	  if (frame_relative_level (this_frame)==0)
//          {
//        	  value=get_frame_register_unsigned (this_frame, TRICORE_A11_REGNUM);
//        	  result=frame_unwind_got_constant (this_frame,regnum,value);
//              if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result A11 lval %d %8.8lx\n",value_lval_const(result),value);
//        	  return result;
//          }
//


      }
    case TRICORE_PCXI_REGNUM:
      {
        gdb_byte buf[4];
        memset (&buf[0], 0, 4);
//        if (frame_relative_level (this_frame)==0)
//        {
//      	  value=get_frame_register_unsigned (this_frame, TRICORE_PCXI_REGNUM);
//      	  result=frame_unwind_got_constant (this_frame,regnum,value);
//            if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result PCXI lval %d\n",value_lval_const(result));
//      	  return result;
//        }
        pcxi = get_frame_register_unsigned (this_frame, TRICORE_PCXI_REGNUM);
          {
        if (pcxi!=0)
          {
          pcxi_addr= ((pcxi & 0xF0000) << 12) + ((pcxi & 0xFFFF) << 6);
          target_read_memory (pcxi_addr, &buf[0],4);
          value = (ULONGEST) extract_unsigned_integer (&buf[0],4,byte_order);
          }
        else
          {
            value=0;
          }
          }
       if (tricore_debug)
         {
           debug_printf ("***tric_dwarf2_prev_register %d PCXI %8.8lx ",frame_relative_level (this_frame),pcxi);
           debug_printf (" PCXIAddr %8.8lx ",pcxi_addr);
           debug_printf (" New PCXI %8.8lx \n",value);
         }
       result=frame_unwind_got_address (this_frame, regnum, value);
       if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result PCXI lval %d\n",value_lval_const(result));
      return result;
      }
    case TRICORE_SP_REGNUM:
    {
  	gdb_byte buf[4];
      memset (&buf[0], 0, 4);
      pcxi = get_frame_register_unsigned (this_frame, TRICORE_PCXI_REGNUM);
      if (pcxi!=0)
        {
        pcxi_addr= ((pcxi & 0xF0000) << 12) + ((pcxi & 0xFFFF) << 6);
        }
      else
        {
        }
      result=frame_unwind_got_memory (this_frame, regnum,pcxi_addr+8);
      return result;
//        value=read_memory_unsigned_integer (pcxi_addr+12, 4,byte_order); //PCXI
//
//        if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result A11 via PCXI lval %d %8.8lx\n",value_lval_const(result),value);
//
//    	  if (frame_relative_level (this_frame)==0)
//          {
//        	  value=get_frame_register_unsigned (this_frame, TRICORE_A11_REGNUM);
//        	  result=frame_unwind_got_constant (this_frame,regnum,value);
//              if (tricore_debug) debug_printf ("***tric_dwarf2_prev_register result A11 lval %d %8.8lx\n",value_lval_const(result),value);
//        	  return result;
//          }
//


    }
    default:
      internal_error (__FILE__, __LINE__,
                      _("Unexpected register %d"), regnum);
    }
return NULL;
}


static void
tricore_dwarf2_frame_init_reg (struct gdbarch *gdbarch, int regnum,
                               struct dwarf2_frame_state_reg *reg,
                               struct frame_info *this_frame)
{
	if (get_frame_type (this_frame) == DUMMY_FRAME)
	{
		debug_printf ("***tric_dwarf2_frame_init_reg DUMMY_FRAME\n");
	}

	if ((regnum==TRICORE_PC_REGNUM) || (regnum==TRICORE_PCXI_REGNUM) || (regnum==TRICORE_A11_REGNUM))
    {
      if (tricore_debug) debug_printf ("***tric_dwarf2_frame_init_reg %d\n",regnum);
    }
  // the dwarf unwinder needs a preunwinder to eleminate frames which dwarf unwinder can not handle
  // the frame sniffer order is tricore_frame_status (which takes the strange ones), then dwarf and others and finally the tricore_frame_default

  switch (regnum)
    {
    case TRICORE_PCXI_REGNUM:
      {
      reg->how = DWARF2_FRAME_REG_FN;
      reg->loc.fn = tricore_dwarf2_prev_register;
      break;
      }
    //TODO fixes FP issues, unknown is if other upper registers eg. A12/15.... have to be extracted in a similar way
    //in addition see the hook set_gdbarch_deprecated_fp_regnum (gdbarch, TRICORE_FP_REGNUM); which is point to A10
    case TRICORE_A14_REGNUM:
      {
      reg->how = DWARF2_FRAME_REG_FN;
      reg->loc.fn = tricore_dwarf2_prev_register;
      break;
      }
    case TRICORE_A11_REGNUM:
      {
      reg->how = DWARF2_FRAME_REG_FN;
      reg->loc.fn = tricore_dwarf2_prev_register;
      break;
      }
    case TRICORE_PC_REGNUM:
      {
      reg->how = DWARF2_FRAME_REG_FN;
      reg->loc.fn = tricore_dwarf2_prev_register;
      break;
      }
    case TRICORE_SP_REGNUM:
      reg->how = DWARF2_FRAME_REG_CFA;
//      reg->how = DWARF2_FRAME_REG_FN;
//      reg->loc.fn = tricore_dwarf2_prev_register;
      break;
    }
}

static bool tricore_execute_dwarf_cfa_vendor_op (struct gdbarch *gdbarch, gdb_byte op,
                                   struct dwarf2_frame_state *fs)
{
  if (tricore_debug)
    debug_printf ("***tric_execute_dwarf_cfa_vendor_op %x\n",op);
  return (false);
}

static int
tricore_breakpoint_kind_from_pc (struct gdbarch *gdbarch, CORE_ADDR *pcptr)
{
  //the kind type is always 4, you will see th ekind type in the breakpoint packages for client-server communication
  //sw breakpoints will be migrated to hw breakpoints in the server
  //I dont like the approach to work with sw debug breakpoints in targets which are support hw breakpoints, in addition the usage of sw breakpoints is limited to rw memories
  return 4;
}

static const gdb_byte *
tricore_sw_breakpoint_from_kind (struct gdbarch *gdbarch, int kind, int *size)
{
  //no sw breakpoints
  return NULL;
}

static CORE_ADDR
tricore_frame_align (struct gdbarch *gdbarch, CORE_ADDR sp)
{
  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_frame_align \n");
  return sp & ~3;
}

static int
tricore_print_insn_delayed (bfd_vma addr, struct disassemble_info *info)
{
  if ((info->disassembler_options == NULL) && (info->section == NULL))
    {
      struct obj_section *s = find_pc_section (addr);
      if (s != NULL)
        info->section = s->the_bfd_section;
    }
 return default_print_insn (addr, info);
}

static CORE_ADDR
tricore_frame_base_address (struct frame_info *this_frame, void **this_cache)
{
  if (tricore_debug)
  fprintf_unfiltered (gdb_stdlog,"***tricore_frame_base_address \n");
  struct tricore_frame_cache *cache = tricore_frame_unwind_cache (this_frame, this_cache);
  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_frame_base_address base=%8.8lx\n",cache->base);
  return cache->base;
}

/* Functions defining the architecture.  */
static const struct frame_base tricore_frame_base = {
  &tricore_frame_default_unwind,
  tricore_frame_base_address,
  tricore_frame_base_address,
  tricore_frame_base_address
};

static struct frame_id
tricore_dummy_id (struct gdbarch *gdbarch, struct frame_info *this_frame)
{
  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_dummy_id\n");
  CORE_ADDR sp = get_frame_register_unsigned (this_frame,
                                              gdbarch_sp_regnum (gdbarch));
  CORE_ADDR pcxi_addr = get_frame_register_unsigned (this_frame,TRICORE_PCXI_REGNUM );
  pcxi_addr= ((pcxi_addr & 0xF0000) << 12) + ((pcxi_addr & 0xFFFF) << 6);
  CORE_ADDR pc=get_frame_pc (this_frame);
  if (tricore_debug)
      fprintf_unfiltered (gdb_stdlog, "***tricore_dummy_id build sp=%8.8lx pc=%8.8lx pcxi=%8.8lx\n",sp, pc,pcxi_addr);
  return frame_id_build_special (sp, pc,pcxi_addr);
}


static CORE_ADDR
tricore_push_word (struct gdbarch *gdbarch, CORE_ADDR sp, ULONGEST word)
{
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  write_memory_unsigned_integer (sp, 4, byte_order, word);
  sp-=4;
  return sp;
}

static CORE_ADDR
tricore_push_dummy_call (struct gdbarch *gdbarch, struct value *function,
                      struct regcache *regcache, CORE_ADDR bp_addr,
                      int nargs, struct value **args, CORE_ADDR sp,
                      function_call_return_method return_method, CORE_ADDR struct_addr)
{
  int i, argnum, len, num_rest_args, pass, firstreg;
  char *rest_args, *use_reg;
  gdb_byte *val,valbuf[INT_REGISTER_SIZE];
  struct value *arg;
  struct type *arg_type;
  enum type_code typecode;
  char addr_reg_used[4], data_reg_used[4];
  CORE_ADDR new_sp, regval;
  ULONGEST uvalue;
  CORE_ADDR csa_sp;
  enum bfd_endian byte_order = gdbarch_byte_order (gdbarch);
  rest_args=NULL;
  if (tricore_debug) printf ("*** tricore_push_dummy_call bp=%8.8lx sp=%8.8lx struct_addr=%8.8lx\n",bp_addr,sp,struct_addr);

  CORE_ADDR pcxi, fcx, new_fcx, csa, psw,icr;
  regcache_cooked_read_unsigned (regcache, TRICORE_PCXI_REGNUM,&uvalue);
  pcxi = uvalue;
  regcache_cooked_read_unsigned (regcache, TRICORE_FCX_REGNUM,&uvalue);
  fcx = uvalue;
  regcache_cooked_read_unsigned (regcache, TRICORE_ICR_REGNUM,&uvalue);
  icr = uvalue;
  csa = ((fcx & 0xffff) << 6) | ((fcx & 0xf0000) << 12);
  new_fcx = read_memory_integer (csa, 4,byte_order);

          (void) tricore_push_word (gdbarch, csa, pcxi); //this is like a start from scratch
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_PSW_REGNUM,&uvalue);
          psw=uvalue;
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_A10_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, sp);
          csa_sp=csa;
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_A11_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_D8_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_D9_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_D10_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_D11_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_A12_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_A13_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_A14_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_A15_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_D12_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_D13_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_D14_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
          regcache_cooked_read_unsigned (regcache, TRICORE_D15_REGNUM,&uvalue);
          (void) tricore_push_word (gdbarch,csa, uvalue);
          csa += 4;
     pcxi = fcx;
     fcx = new_fcx & 0xfffff;
  /* Write back the new PCXI and FCX values.  */
  /* it is upper context save and PCPN and PIE from isr */
  regcache_cooked_write_unsigned (regcache,TRICORE_PCXI_REGNUM, (pcxi & 0xfffff) | 0x100000 | ((icr & 0xff)<<22) | ((icr & 0x8000)<<6) );
  regcache_cooked_write_unsigned (regcache,TRICORE_FCX_REGNUM, fcx);
  regcache_cooked_read_unsigned (regcache, TRICORE_PC_REGNUM,&uvalue);
  //update the psw, towards cdc usage
  regcache_cooked_write_unsigned (regcache,TRICORE_PSW_REGNUM, psw | 0x7f); //disable cdc counting
  if (tricore_debug) printf ("*** tricore_push_dummy_call pc=%8.8lx\n",uvalue);
  regcache_cooked_write_unsigned (regcache,TRICORE_A11_REGNUM, bp_addr);

  //TODO this is new in gdb10
  if (return_method == return_method_hidden_param)
    {
      args++;
      nargs--;
      if (tricore_debug)
        {
          debug_printf ("*** tricore_push_dummy_call hidden param nargs decremented %d\n",nargs);
        }
    }

  new_sp = sp;
  num_rest_args = nargs;
  rest_args = (char *) malloc(nargs);
  memset (rest_args, 0, nargs);
  memset (addr_reg_used, 0, 4);
  memset (data_reg_used, 0, 4);
  if (return_method == return_method_struct)
      {
        regcache_cooked_write_unsigned (regcache,TRICORE_A4_REGNUM, struct_addr);
        addr_reg_used[0] = 1;
      }

  if (nargs > 0)
  {

  //TODO this is new in gdb10
  if (return_method != return_method_normal)
    {
      if (tricore_debug)
        {
          debug_printf ("*** tricore_push_dummy_call no normal return %s = 0x%s\n",
                        gdbarch_register_name (gdbarch,
                                               TRICORE_A4_REGNUM),
                        paddress (gdbarch, struct_addr));
        }
      regcache_cooked_write_unsigned (regcache,TRICORE_A4_REGNUM, struct_addr);
      addr_reg_used[0] = 1;
    }
//  if (struct_return)
//    {
//      regcache_cooked_write_unsigned (regcache,TRICORE_A4_REGNUM, struct_addr);
//      addr_reg_used[0] = 1;
//    }

  /* Pass 0: handle register arguments;  pass 1: handle stack args.
     The tricky part is that pass 0 scans the args left-to-right,
     while pass 1 does it the other way around (so that the leftmost
     stack arg can be found where new_sp points to).  */
  for (pass = 0; pass <= 1; ++pass)
    {
      argnum = pass ? nargs : -1;
      while (num_rest_args)
        {
          argnum += pass ? -1 : 1;
          if ((argnum < 0) || (argnum == nargs))
            break;
//TODO VARARG Handling
//          if ((pass == 0) && (argnum == tricore_nargs))
//            /* The user passed more arguments than the function actually
//               takes.  This may or may not be an error (we can't check
//               this, because there's no way to find out if a function's
//               last parameter is an ellipsis), but anyway, we need to
//               pass the additional arguments on the stack.  If a function
//               takes a variable number of arguments, then it expects all
//               non-fixed args on the stack.  If the function to be called
//               takes a fixed number of arguments, it won't hurt if we
//               pass the additional args on the stack, as they're silently
//               ignored, anyway.  */
//            break;

          if (rest_args[argnum])
            continue;  /* Arg already put in a register.  */

          arg = args[argnum];
          arg_type=value_type (arg);
          len = TYPE_LENGTH (arg_type);
          typecode = arg_type->code();
          if (tricore_debug) printf("pass=%d argnum=%d len=%d typecode=%d\n",pass,argnum,len,typecode);
          /* According to the EABI, structure arguments whose size is
             greater than 64 bits have to be passed by reference.  */
          if ((len > 8)
              && ((typecode == TYPE_CODE_STRUCT)
                  || (typecode == TYPE_CODE_UNION) || (typecode == TYPE_CODE_COMPLEX)))
            {
              store_unsigned_integer (valbuf, INT_REGISTER_SIZE,byte_order, value_address (arg));
              typecode = TYPE_CODE_PTR;
              len = INT_REGISTER_SIZE;
              val = valbuf;
            }
          else
              val= (gdb_byte *) value_contents_all (args[argnum]);
          if (pass == 0)  /* Store arg in registers.  */
            {
              if ((typecode == TYPE_CODE_PTR) || (typecode == TYPE_CODE_REF))
                {
                  use_reg = addr_reg_used;
                  firstreg = TRICORE_A4_REGNUM;
                }
              else
                {
                  use_reg = data_reg_used;
                  firstreg = TRICORE_D4_REGNUM;
                }

              /* 8-byte entities must be passed in even-numbered regs.  */
              if ((len > INT_REGISTER_SIZE) && (len <= 8))
                {
                  i = -1;
                  if ((use_reg[0] == 0) && (use_reg[1] == 0))
                    i = 0;
                  else if ((use_reg[2] == 0) && (use_reg[3] == 0))
                    i = 2;

                  if (i < 0)
                    continue;  /* No extended/double reg available.  */

                  regval = extract_unsigned_integer (val, INT_REGISTER_SIZE,byte_order);
                  regcache_cooked_write_unsigned (regcache,firstreg + i, regval);
                  regval = extract_unsigned_integer (val + 4, INT_REGISTER_SIZE,byte_order);
                  regcache_cooked_write_unsigned (regcache,firstreg + i + 1, regval);
                  use_reg[i] = use_reg[i + 1] = 1;
                  rest_args[argnum] = 1;
                  --num_rest_args;
                }
              else if (len <= INT_REGISTER_SIZE)
                {
                  for (i = 0; i < 4; ++i)
                    if (!use_reg[i])
                      break;

                  if (i == 4)
                    continue;  /* No more free register for this type.  */

                  regval = extract_signed_integer (val, len,byte_order);
                  regcache_cooked_write_unsigned (regcache,firstreg + i, regval);
                  if (tricore_debug) printf("argnum=%d regnr=%d value=%8.8lx\n",argnum,firstreg + i,regval);
                  use_reg[i] = 1;
                  rest_args[argnum] = 1;
                  --num_rest_args;
                }
              else
                error ("Invalid argument length %d in push_arguments pass 0", len);
            }
          else /* Pass 1: push arg on stack.  */
            {
              if ((len > INT_REGISTER_SIZE) && (len <= 8))
                {
                  regval = extract_unsigned_integer (val + 4, INT_REGISTER_SIZE,byte_order);
                  new_sp=new_sp-4;
                  (void) tricore_push_word (gdbarch,new_sp, regval);
                  regval = extract_unsigned_integer (val, INT_REGISTER_SIZE,byte_order);
                  new_sp=new_sp-4;
                  (void) tricore_push_word (gdbarch,new_sp, regval);
                  rest_args[argnum] = 1;
                  --num_rest_args;
                }
              else if (len <= INT_REGISTER_SIZE)
                {
                  regval = extract_unsigned_integer (val, INT_REGISTER_SIZE,byte_order);
                  new_sp=new_sp-4;
                  if (tricore_debug) printf("argnum=%d sp=%8.8lx value=%8.8lx\n",argnum, new_sp,regval);
                  (void) tricore_push_word (gdbarch,new_sp, regval);
                  rest_args[argnum] = 1;
                  --num_rest_args;
                }
              else
                error ("Invalid argument length %d in push_arguments pass 1", len);
            }
        }
    }
  }
  else
    {
      new_sp=sp;
    }
  if (rest_args!=NULL) free (rest_args);

  if (tricore_debug) printf ("*** tricore_push_dummy_call sp=%8.8lx new_sp=%8.8lx \n",sp,new_sp);
  regcache_cooked_write_unsigned (regcache, TRICORE_SP_REGNUM, new_sp);
  (void) tricore_push_word (gdbarch,csa_sp, new_sp);
  return new_sp;
}

static CORE_ADDR
tricore_unwind_pc (struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  CORE_ADDR pc;
  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_unwind_pc  level=%d\n",frame_relative_level (next_frame));

  pc = frame_unwind_register_unsigned (next_frame, TRICORE_PC_REGNUM);

  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_unwind_pc, pc=%s\n",
                        paddress (gdbarch, pc));
  return pc;
}

/* Implement the unwind_sp gdbarch method.  */

static CORE_ADDR
tricore_unwind_sp (struct gdbarch *gdbarch, struct frame_info *next_frame)
{
  CORE_ADDR sp;
  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_unwind_sp level=%d\n",
                        frame_relative_level (next_frame));

  sp = frame_unwind_register_unsigned (next_frame, TRICORE_SP_REGNUM);

  if (tricore_debug)
    fprintf_unfiltered (gdb_stdlog, "***tricore_unwind_sp, sp=%s\n",
                        paddress (gdbarch, sp));

  return sp;
}


static struct gdbarch *
tricore_gdbarch_init (struct gdbarch_info info, struct gdbarch_list *arches)
{
  struct gdbarch_tdep *tdep;
  struct gdbarch *gdbarch;
  struct tdesc_arch_data *tdesc_data = NULL;
  const struct bfd_arch_info *binfo;
  const struct target_desc *tdesc = info.target_desc;

  /* If there is already a candidate, use it.  */
  arches = gdbarch_list_lookup_by_info (arches, &info);
  if (arches != NULL)
    return arches->gdbarch;
  if (tdesc == NULL) {
	initialize_tdesc_tricore ();
    tdesc = tdesc_tricore;
  }
    

  /* Check any target description for validity.  */
  if (tdesc_has_registers (tdesc))
    {
      const struct tdesc_feature *feature;
      int valid_p;
      int i;
      feature = tdesc_find_feature (tdesc,
                                    "org.gnu.gdb.tricore.core");
      if (feature == NULL)
        return NULL;
      tdesc_data = tdesc_data_alloc ();

      valid_p = 1;
      for (i = 0; i < TRICORE_NUM_REGS; i++)
        valid_p &= tdesc_numbered_register (feature, tdesc_data, i,
                                            tricore_register_names[i]);
      if (!valid_p)
        {
          tdesc_data_cleanup (tdesc_data);
          return NULL;
        }
    }

  /* Allocate space for the new architecture.  */
  binfo = info.bfd_arch_info;
  tdep = XCNEW (struct gdbarch_tdep);
  gdbarch = gdbarch_alloc (&info, tdep);
  tdep->info = &info;

  /* Target data types */
  set_gdbarch_short_bit (gdbarch, 16);
  set_gdbarch_int_bit (gdbarch, 32);
  set_gdbarch_long_bit (gdbarch, 32);
  set_gdbarch_long_long_bit (gdbarch, 64);
  set_gdbarch_float_bit (gdbarch, 32);
  set_gdbarch_float_format (gdbarch, floatformats_ieee_single);
  set_gdbarch_double_bit (gdbarch, 64);
  set_gdbarch_double_format (gdbarch, floatformats_ieee_double);
  set_gdbarch_long_double_bit (gdbarch, 64);
  set_gdbarch_long_double_format (gdbarch, floatformats_ieee_double);
  set_gdbarch_ptr_bit (gdbarch, binfo->bits_per_address);
  set_gdbarch_addr_bit (gdbarch, binfo->bits_per_address);
  set_gdbarch_char_signed (gdbarch, 1);

  /* Register info */
  set_gdbarch_num_regs (gdbarch, TRICORE_NUM_REGS);
  set_gdbarch_pc_regnum (gdbarch, TRICORE_PC_REGNUM);
  set_gdbarch_sp_regnum (gdbarch, TRICORE_SP_REGNUM);
  //set_gdbarch_deprecated_fp_regnum (gdbarch, TRICORE_FP_REGNUM);
  set_gdbarch_ps_regnum (gdbarch, TRICORE_PSW_REGNUM);
  set_gdbarch_num_pseudo_regs (gdbarch, 0);
  set_gdbarch_register_name (gdbarch, tricore_register_name);

/* Frame and stack info */
  set_gdbarch_skip_prologue (gdbarch, tricore_skip_prologue);
  set_gdbarch_inner_than (gdbarch, core_addr_lessthan);
  //set_gdbarch_frame_num_args (gdbarch, tricore_frame_num_args);
  dwarf2_frame_set_init_reg (gdbarch, tricore_dwarf2_frame_init_reg);
  set_gdbarch_execute_dwarf_cfa_vendor_op (gdbarch,tricore_execute_dwarf_cfa_vendor_op);
  /* Unwind the frame.  */
  //in a first step we take a generic unwinder based on registers
  //extraordeinary cases will be handled here, incl. stop reason-> remaining will be handed over to dwarf unwinders
  frame_unwind_append_unwinder (gdbarch, &tricore_frame_status_unwind);
  //dwarf unwinders
  dwarf2_append_unwinders (gdbarch);
  //what was not captured by the first two unwinder groups will be handled again by a more generic unwinder
  frame_unwind_append_unwinder (gdbarch, &tricore_frame_default_unwind);
  frame_base_append_sniffer (gdbarch, dwarf2_frame_base_sniffer);


  set_gdbarch_decr_pc_after_break (gdbarch, 0);
  set_gdbarch_frame_args_skip (gdbarch, 0);

  /* Return value info */
  //set_gdbarch_deprecated_extract_struct_value_address (gdbarch, tricore_extract_struct_value_address);
   
 
  //set_gdbarch_deprecated_push_return_address (gdbarch, tricore_push_return_address);
  //set_gdbarch_deprecated_reg_struct_has_addr (gdbarch, tricore_reg_struct_has_addr);
  //set_gdbarch_extract_return_value (gdbarch, tricore_extract_return_value);
  //set_gdbarch_store_return_value (gdbarch, tricore_store_return_value);


  /* Breakpoint support */
  set_gdbarch_breakpoint_kind_from_pc (gdbarch,tricore_breakpoint_kind_from_pc);
  set_gdbarch_sw_breakpoint_from_kind (gdbarch,tricore_sw_breakpoint_from_kind);
  set_gdbarch_breakpoint_from_pc (gdbarch, tricore_breakpoint_from_pc);
  set_gdbarch_have_nonsteppable_watchpoint (gdbarch, 1);
  set_gdbarch_return_value (gdbarch, tricore_return_value);
  set_gdbarch_frame_align (gdbarch, tricore_frame_align);
  set_gdbarch_unwind_pc (gdbarch, tricore_unwind_pc);
  set_gdbarch_unwind_sp (gdbarch, tricore_unwind_sp);

  set_gdbarch_push_dummy_call (gdbarch, tricore_push_dummy_call);
  set_gdbarch_dummy_id (gdbarch, tricore_dummy_id);

  frame_base_set_default (gdbarch, &tricore_frame_base);
  //TODO newlib,libc,tricore.md, tricore.c, builtin
  //set_gdbarch_get_longjmp_target (gdbarch, tricore_get_longjmp_target);
  set_gdbarch_print_insn (gdbarch, tricore_print_insn_delayed);

  /* Hook in OS ABI-specific overrides, if they have been registered.  */
  gdbarch_init_osabi (info, gdbarch);
  
  if (tdesc_data != NULL)
    tdesc_use_registers (gdbarch, tdesc, tdesc_data);

  return gdbarch;
}

#ifdef __VIRTUAL_IO__
/* The stuff below implements "virtual I/O" that lets TriCore programs
   running on some target hardware (or a simulator) use the host OS to
   do file I/O.  It is assumed that programs are linked against the
   "newlib" standard C library and the "libos" support library.  */


/* Target address of the ___virtio function.  */

static CORE_ADDR tricore_virtio_addr;

/* 1 if at least one file was opened.  */

static int tricore_vio_in_use = 0;

/* The following system calls are supported.  */

#define SYS__OPEN        0x01
#define SYS__CLOSE       0x02
#define SYS__LSEEK       0x03
#define SYS__READ        0x04
#define SYS__WRITE       0x05
#define SYS__CREAT       0x06
#define SYS__UNLINK      0x07
#define SYS__STAT        0x08
#define SYS__FSTAT       0x09
#define SYS__GETTIME     0x0a

#define NL_O_RDONLY     0x00001
#define NL_O_WRONLY     0x00002
#define NL_O_RDWR       0x00003
#define NL_O_APPEND     0x00008
#define NL_O_CREAT      0x00200
#define NL_O_TRUNC      0x00400
#define NL_O_EXCL       0x00800
#define NL_O_NDELAY     0x01000
#define NL_O_SYNC       0x02000
#define NL_O_NONBLOCK   0x04000
#define NL_O_NOCTTY     0x08000
#define NL_O_BINARY     0x10000

#define NL_S_IRWXU      000700
#define NL_S_IRUSR      000400
#define NL_S_IWUSR      000200
#define NL_S_IXUSR      000100
#define NL_S_IRWXG      000070
#define NL_S_IRGRP      000040
#define NL_S_IWGRP      000020
#define NL_S_IXGRP      000010
#define NL_S_IRWXO      000007
#define NL_S_IROTH      000004
#define NL_S_IWOTH      000002
#define NL_S_IXOTH      000001

#define NL_SEEK_SET     0
#define NL_SEEK_CUR     1
#define NL_SEEK_END     2

#define NL_EPERM        1
#define NL_ENOENT       2
#define NL_ESRCH        3
#define NL_EINTR        4
#define NL_EIO          5
#define NL_ENXIO        6
#define NL_E2BIG        7
#define NL_ENOEXEC      8
#define NL_EBADF        9
#define NL_ECHILD       10
#define NL_EAGAIN       11
#define NL_ENOMEM       12
#define NL_EACCES       13
#define NL_EFAULT       14
#define NL_ENOTBLK      15
#define NL_EBUSY        16
#define NL_EEXIST       17
#define NL_EXDEV        18
#define NL_ENODEV       19
#define NL_ENOTDIR      20
#define NL_EISDIR       21
#define NL_EINVAL       22
#define NL_ENFILE       23
#define NL_EMFILE       24
#define NL_ENOTTY       25
#define NL_ETXTBSY      26
#define NL_EFBIG        27
#define NL_ENOSPC       28
#define NL_ESPIPE       29
#define NL_EROFS        30
#define NL_EMLINK       31
#define NL_EPIPE        32
#define NL_ENOSYS       88
#define NL_ENOTEMPTY    90
#define NL_ENAMETOOLONG 91

/* Max number of files a program may have open simultaneously.  */

#define MAX_VIO_FILES   10

typedef struct _vio_file
{
  char *pathname;       /* Name of the file.  */
  int desc;             /* File descriptor (the slot number, actually).  */
  int mode;             /* Mode that was given in the open/creat call.  */
  int orig_flags;       /* Flags that were given in the open/creat call.  */
  int new_flags;        /* Flags to use when re-opening the file.  */
  off_t offset;         /* Current file offset.  */
  int is_valid;         /* 1 if descriptor is valid.  */
} vio_file;

vio_file tricore_vio_files[MAX_VIO_FILES];

/* Lookup a symbol by name.  */

static CORE_ADDR tricore_find_symbol_address (const char *name)
{
  struct bound_minimal_symbol minsym;

  minsym = lookup_minimal_symbol (name, NULL, NULL);
  if (minsym.minsym)
    return BMSYMBOL_VALUE_ADDRESS (minsym);
  else
    return (CORE_ADDR)-1;
//TODO don't like this translation, to often misleading
#if 0
  struct symbol *sym;
  register int i;
  int  iafot = 1;
  long val;

  sym = lookup_symbol (name, NULL, VAR_NAMESPACE, &iafot, NULL);
  if (sym == NULL)
    {
      if (iafot)
        return (CORE_ADDR) -1;
      else
        {
          sym = (struct symbol *)
                 lookup_minimal_symbol (name, NULL, (struct objfile *) NULL);
          if (sym == NULL)
            return (CORE_ADDR) -1;

          return (CORE_ADDR) (SYMBOL_VALUE_ADDRESS (sym));
        }
    }
  else
    {
      val = SYMBOL_VALUE (sym);
      switch (SYMBOL_CLASS (sym))
        {
        case LOC_LABEL:
          return (CORE_ADDR) val;

        case LOC_BLOCK:
          return (CORE_ADDR) (BLOCK_START (SYMBOL_BLOCK_VALUE (sym)));

        default:
          return (CORE_ADDR) -1;
        }
    }
#endif
}

/* Initialize virtual I/O.  This is called after a "target" command
   and whenever an inferior is created (usually after a "run" command).  */

void tricore_vio_init (void)
{
  int i;

  tricore_virtio_addr = tricore_find_symbol_address ("___virtio");
  if (tricore_vio_in_use)
    for (i = 3; i < MAX_VIO_FILES; ++i)
      if (tricore_vio_files[i].pathname != NULL)
        free (tricore_vio_files[i].pathname);
  memset (tricore_vio_files, 0, sizeof (tricore_vio_files));
  tricore_vio_files[0].is_valid = 1;  /* stdin  */
  tricore_vio_files[1].is_valid = 1;  /* stdout  */
  tricore_vio_files[2].is_valid = 1;  /* stderr  */
  tricore_vio_in_use = 0;
}

/* Map host's errno value to newlib's equivalent.  */

static int
tricore_vio_map_errno (int host_errno)
{
  switch (host_errno)
    {
#ifdef EPERM
    case EPERM: return NL_EPERM;
#endif
#ifdef ENOENT
    case ENOENT: return NL_ENOENT;
#endif
#ifdef ESRCH
    case ESRCH: return NL_ESRCH;
#endif
#ifdef EINTR
    case EINTR: return NL_EINTR;
#endif
#ifdef EIO
    case EIO: return NL_EIO;
#endif
#ifdef ENXIO
    case ENXIO: return NL_ENXIO;
#endif
#ifdef E2BIG
    case E2BIG: return NL_E2BIG;
#endif
#ifdef ENOEXEC
    case ENOEXEC: return NL_ENOEXEC;
#endif
#ifdef EBADF
    case EBADF: return NL_EBADF;
#endif
#ifdef ECHILD
    case ECHILD: return NL_ECHILD;
#endif
#ifdef EAGAIN
    case EAGAIN: return NL_EAGAIN;
#endif
#ifdef ENOMEM
    case ENOMEM: return NL_ENOMEM;
#endif
#ifdef EACCES
    case EACCES: return NL_EACCES;
#endif
#ifdef EFAULT
    case EFAULT: return NL_EFAULT;
#endif
#ifdef ENOTBLK
    case ENOTBLK: return NL_ENOTBLK;
#endif
#ifdef EBUSY
    case EBUSY: return NL_EBUSY;
#endif
#ifdef EEXIST
    case EEXIST: return NL_EEXIST;
#endif
#ifdef EXDEV
    case EXDEV: return NL_EXDEV;
#endif
#ifdef ENODEV
    case ENODEV: return NL_ENODEV;
#endif
#ifdef ENOTDIR
    case ENOTDIR: return NL_ENOTDIR;
#endif
#ifdef EISDIR
    case EISDIR: return NL_EISDIR;
#endif
#ifdef EINVAL
    case EINVAL: return NL_EINVAL;
#endif
#ifdef ENFILE
    case ENFILE: return NL_ENFILE;
#endif
#ifdef EMFILE
    case EMFILE: return NL_EMFILE;
#endif
#ifdef ENOTTY
    case ENOTTY: return NL_ENOTTY;
#endif
#ifdef ETXTBSY
    case ETXTBSY: return NL_ETXTBSY;
#endif
#ifdef EFBIG
    case EFBIG: return NL_EFBIG;
#endif
#ifdef ENOSPC
    case ENOSPC: return NL_ENOSPC;
#endif
#ifdef ESPIPE
    case ESPIPE: return NL_ESPIPE;
#endif
#ifdef EROFS
    case EROFS: return NL_EROFS;
#endif
#ifdef EMLINK
    case EMLINK: return NL_EMLINK;
#endif
#ifdef EPIPE
    case EPIPE: return NL_EPIPE;
#endif
#ifdef ENOSYS
    case ENOSYS: return NL_ENOSYS;
#endif
#ifdef ENOTEMPTY
    case ENOTEMPTY: return NL_ENOTEMPTY;
#endif
#ifdef ENAMETOOLONG
    case ENAMETOOLONG: return NL_ENAMETOOLONG;
#endif
    default: return (host_errno);
    }
}

/* Set return and errno values;  the ___virtio function takes care
   that the target's errno variable gets updated from %d12, and
   eventually moves %d11 to the return register (%d2).  */

static void tricore_vio_set_result (int retval, int host_errno)
{
  struct regcache *regcache = get_current_regcache ();
  regcache_cooked_write_signed (regcache, TRICORE_D11_REGNUM,retval);
  regcache_cooked_write_signed (regcache, TRICORE_D12_REGNUM,tricore_vio_map_errno (host_errno));
  target_store_registers (regcache,-1);
  registers_changed ();
}

/* Perform an open (is_open_call = 1) or creat system call.  */

static void tricore_vio_open_creat (int is_open_call)
{
  char *filename;
  gdb::unique_xmalloc_ptr<char> filename_gdb;
  CORE_ADDR nameptr;
  int namelen;
  int rem_flags, flags, new_flags;
  int retval, tmp_errno;
  //int reterrno;
  int filenr;
  int rem_mode, mode = 0, parse_mode = 0;
  struct regcache *regcache = get_current_regcache ();
  flags=0;
  ULONGEST uvalue;
  LONGEST value;
  for (filenr = 4; filenr < MAX_VIO_FILES; ++filenr)
    if (!tricore_vio_files[filenr].is_valid)
      break;
  if (filenr == MAX_VIO_FILES)
    {
      tricore_vio_set_result (-1, EMFILE);
      return;
    }


  regcache_cooked_read_unsigned (regcache,TRICORE_A4_REGNUM,&uvalue);
  nameptr = (CORE_ADDR) uvalue;
  filename_gdb = target_read_string (nameptr, FILENAME_MAX);
//  filename = (char *) malloc(namelen);
  strcpy(filename,filename_gdb.get());
  if (retval != 0)
    {
      if (namelen > 0)
        free (filename);
      tricore_vio_set_result (-1, EIO);
      return;
    }

  if (!is_open_call)
    {
      flags = O_CREAT | O_WRONLY | O_TRUNC;
      new_flags = O_WRONLY;
      regcache_cooked_read_signed (regcache,TRICORE_D4_REGNUM,&value);
      rem_mode=(int) value;
      parse_mode = 1;
    }
  else
    {
      regcache_cooked_read_signed (regcache,TRICORE_D4_REGNUM,&value);
      rem_flags =(int) value;
      if (rem_flags & NL_O_CREAT)
        {
          parse_mode = 1;
          regcache_cooked_read_signed (regcache,TRICORE_D5_REGNUM,&value);
          rem_mode=(int) value;
        }
      switch ((rem_flags + 1) & 0x3)
        {
        case 1: flags = O_RDONLY; break;
        case 2: flags = O_WRONLY; break;
        case 3: flags = O_RDWR; break;
        }
      if (rem_flags & NL_O_APPEND)
        flags |= O_APPEND;
      if (rem_flags & NL_O_CREAT)
        flags |= O_CREAT;
      if (rem_flags & NL_O_TRUNC)
        flags |= O_TRUNC;
      if (rem_flags & NL_O_EXCL)
        flags |= O_EXCL;
      if (rem_flags & NL_O_NDELAY)
        flags |= O_NDELAY;
      if (rem_flags & NL_O_SYNC)
        flags |= O_SYNC;
      if (rem_flags & NL_O_NONBLOCK)
        flags |= O_NONBLOCK;
      if (rem_flags & NL_O_NOCTTY)
        flags |= O_NOCTTY;
#ifdef O_BINARY
      if (rem_flags & NL_O_BINARY)
        flags |= O_BINARY;
#endif
      new_flags = flags & ~(O_CREAT | O_TRUNC | O_APPEND);
    }

  if (parse_mode)
    {
      if (rem_mode & NL_S_IRUSR)
        mode |= S_IRUSR;
      if (rem_mode & NL_S_IWUSR)
        mode |= S_IWUSR;
      if (rem_mode & NL_S_IXUSR)
        mode |= S_IXUSR;
      if (rem_mode & NL_S_IRGRP)
        mode |= S_IRGRP;
      if (rem_mode & NL_S_IWGRP)
        mode |= S_IWGRP;
      if (rem_mode & NL_S_IXGRP)
        mode |= S_IXGRP;
      if (rem_mode & NL_S_IROTH)
        mode |= S_IROTH;
      if (rem_mode & NL_S_IWOTH)
        mode |= S_IWOTH;
      if (rem_mode & NL_S_IXOTH)
        mode |= S_IXOTH;
    }

  if (is_open_call)
    {
      if (parse_mode)
        {
        errno=0;
        retval = open (filename, flags, mode);
        tmp_errno = errno;
        }
      else
        {
        retval = open (filename, flags);
        tmp_errno = errno;
        }
    }
  else
    {
      retval = creat (filename, mode);
      tmp_errno = errno;
    }


  if (retval >= 0)
    {
      tricore_vio_files[filenr].pathname = filename;
      tricore_vio_files[filenr].desc = filenr;
      tricore_vio_files[filenr].mode = mode;
      tricore_vio_files[filenr].orig_flags = flags;
      tricore_vio_files[filenr].new_flags = new_flags;
      tricore_vio_files[filenr].is_valid = 1;
      tricore_vio_files[filenr].offset = lseek (retval, 0, SEEK_CUR);
      close (retval);
      tricore_vio_in_use = 1;
    }
  else
    {
      filenr = -1;
      free (filename);
    }
  tricore_vio_set_result (filenr, tmp_errno);
}

/* Perform a close system call.  */

static void tricore_vio_close (void)
{
  int filenr;
  struct regcache *regcache = get_current_regcache ();
  LONGEST value;
  regcache_cooked_read_signed (regcache,TRICORE_D4_REGNUM,&value);
  filenr=(int) value;
  if ((filenr <= 2) || (filenr >= MAX_VIO_FILES)
      || !tricore_vio_files[filenr].is_valid)
    {
      tricore_vio_set_result (-1, EACCES);  /* Well, sort of... ;-)  */
      return;
    }

  if (tricore_vio_files[filenr].pathname != NULL)
    {
      free (tricore_vio_files[filenr].pathname);
      tricore_vio_files[filenr].pathname = NULL;
    }
  tricore_vio_files[filenr].is_valid = 0;
  tricore_vio_set_result (0, 0);
}

/* Perform a read system call.  */

static void tricore_vio_read (void)
{
  int filenr, desc, flags;
  size_t len=0, rlen=0;
  off_t offset;
  CORE_ADDR rem_buf;
  char *filename;
  gdb_byte *buf;
  struct regcache *regcache = get_current_regcache ();
  LONGEST value;
  ULONGEST uvalue;

  regcache_cooked_read_signed (regcache,TRICORE_D4_REGNUM,&value);
  filenr=(int) value;
  if ((filenr < 0) || (filenr >= MAX_VIO_FILES)
      || !tricore_vio_files[filenr].is_valid)
    {
      tricore_vio_set_result (-1, EACCES);  /* Well, sort of... ;-)  */
      return;
    }

  flags = tricore_vio_files[filenr].new_flags;
  filename = tricore_vio_files[filenr].pathname;
  offset = tricore_vio_files[filenr].offset;

  regcache_cooked_read_unsigned (regcache,TRICORE_A4_REGNUM,&uvalue);
  rem_buf=(CORE_ADDR) value;
  regcache_cooked_read_signed (regcache,TRICORE_D5_REGNUM,&value);
  len=(size_t) value;

  if ((buf = (gdb_byte *) malloc (len)) == NULL)
    {
      tricore_vio_set_result (-1, ENOMEM);
      return;
    }

  if (filenr <= 2)
    desc = filenr;
  else
    {
      if ((desc = open (filename, flags)) == -1)
        {
          tricore_vio_set_result (-1, errno);
          free (buf);
          return;
        }
      if (lseek (desc, offset, SEEK_SET) == -1)
        {
          tricore_vio_set_result (-1, errno);
          goto done;
        }
    }
  struct ui_file *gdb_stdtarg;
  struct ui_file *gdb_stdtargerr;
  if (desc<=2)
    {
      if (desc==0) {
    	  rlen=gdb_stdtargin->read ((char *) buf, len);
      }
      if (desc==1)  {
    	  rlen=gdb_stdtarg->read ((char *) buf, len);
      }
      if (desc==2)  {
    	  rlen=gdb_stdtargerr->read ((char *) buf, len);
      }


      if (rlen==-1)
        {
        tricore_vio_set_result (-1, errno);
        goto done;
        }
    }
  else
  if ((rlen = read (desc, buf, len)) == -1)
    {
      tricore_vio_set_result (-1, errno);
      goto done;
    }

  if (target_write_memory (rem_buf, buf, rlen))
    {
      tricore_vio_set_result (-1, EIO);
      goto done;
    }
  tricore_vio_set_result (rlen, 0);

done:
  free (buf);
  if (filenr > 2)
    {
      tricore_vio_files[filenr].offset = lseek (desc, 0, SEEK_CUR);
      close (desc);
    }
}

/* Perform a write system call.  */

static void tricore_vio_write (void)
{
  int filenr, desc, flags;
  size_t len=0, wlen=0;
  off_t offset;
  CORE_ADDR rem_buf;
  char *filename;
  gdb_byte *buf;
  struct regcache *regcache = get_current_regcache ();
  LONGEST value;
  ULONGEST uvalue;
  regcache_cooked_read_signed (regcache,TRICORE_D4_REGNUM,&value);
  filenr=(int) value;
  if ((filenr < 0) || (filenr >= MAX_VIO_FILES)
      || !tricore_vio_files[filenr].is_valid)
    {
      tricore_vio_set_result (-1, EACCES);  /* Well, sort of... ;-)  */
      return;
    }

  flags = tricore_vio_files[filenr].new_flags;
  filename = tricore_vio_files[filenr].pathname;
  offset = tricore_vio_files[filenr].offset;

  regcache_cooked_read_unsigned (regcache,TRICORE_A4_REGNUM,&uvalue);
  rem_buf=(CORE_ADDR) uvalue;
  regcache_cooked_read_signed (regcache,TRICORE_D5_REGNUM,&value);
  len=(size_t) value;
  if ((buf = (gdb_byte *) malloc (len + 1)) == NULL)
    {
      tricore_vio_set_result (-1, ENOMEM);
      return;
    }

  if (target_read_memory (rem_buf, buf, len))
    {
      tricore_vio_set_result (-1, EIO);
      free (buf);
      return;
    }

  if (filenr <= 2)
    desc = filenr;
  else
    {
      if ((desc = open (filename, flags)) == -1)
        {
          tricore_vio_set_result (-1, errno);
          free (buf);
          return;
        }
      if (lseek (desc, offset, SEEK_SET) == -1)
        {
          tricore_vio_set_result (-1, errno);
          goto done;
        }
    }

  if (desc <= 2)
    {
    int i;
//    for (i=0; i<len; i+=1) fprintf_unfiltered (gdb_stdlog, " %d %x",i,buf[i]);
    if (desc==0) {
    	gdb_stdtargin->write ((char *) buf, len);
    }
    if (desc==1) {
    	gdb_stdtarg->write ((char *) buf, len);
    }
    if (desc==2) {
    	gdb_stdtargerr->write ((char *) buf, len);
    }
    tricore_vio_set_result (len, 0);
    }
  else
    {
  if ((wlen = write (desc, buf, len)) == -1)
    {
      tricore_vio_set_result (-1, errno);
      goto done;
    }
  tricore_vio_set_result (wlen, 0);
    }

done:
  free (buf);
  if (filenr > 2)
    {
      tricore_vio_files[filenr].offset = lseek (desc, 0, SEEK_CUR);
      close (desc);
    }
}

/* Perform a lseek system call.  */

static void tricore_vio_lseek (void)
{
  int filenr, desc, whence, flags;
  off_t offset;
  char *filename;
  struct regcache *regcache = get_current_regcache ();
  LONGEST value;
  regcache_cooked_read_signed (regcache,TRICORE_D4_REGNUM,&value);
  filenr=(int) value;
  if ((filenr <= 2) || (filenr >= MAX_VIO_FILES)
      || !tricore_vio_files[filenr].is_valid)
    {
      tricore_vio_set_result (-1, EACCES);  /* Well, sort of... ;-)  */
      return;
    }

  flags = tricore_vio_files[filenr].new_flags;
  filename = tricore_vio_files[filenr].pathname;
  if ((desc = open (filename, flags)) < 0)
    {
      tricore_vio_set_result (-1, errno);
      return;
    }

  regcache_cooked_read_signed (regcache,TRICORE_D5_REGNUM,&value);
  offset=(off_t) value;
  regcache_cooked_read_signed (regcache,TRICORE_D6_REGNUM,&value);
  whence=(int) value;
  if (whence == NL_SEEK_CUR)
    if (lseek (desc, tricore_vio_files[filenr].offset, SEEK_CUR) == -1)
      {
        close (desc);
        tricore_vio_set_result (-1, errno);
        return;
      }

  switch (whence)
    {
    case NL_SEEK_SET: whence = SEEK_SET; break;
    case NL_SEEK_CUR: whence = SEEK_CUR; break;
    case NL_SEEK_END: whence = SEEK_END; break;
    default:
      tricore_vio_set_result (-1, EINVAL);
      close (desc);
      return;
    }

  tricore_vio_files[filenr].offset = lseek (desc, offset, whence);
  tricore_vio_set_result (tricore_vio_files[filenr].offset, errno);
  close (desc);
}

/* Perform an unlink system call.  */

static void tricore_vio_unlink (void)
{
  char *filename;
  gdb::unique_xmalloc_ptr<char> filename_gdb;
  CORE_ADDR nameptr;
  int namelen, retval;
  struct regcache *regcache = get_current_regcache ();
  ULONGEST uvalue;

  regcache_cooked_read_unsigned (regcache,TRICORE_A4_REGNUM,&uvalue);
  nameptr =(CORE_ADDR) uvalue;
  filename_gdb = target_read_string (nameptr, FILENAME_MAX);
  //filename=(char *) malloc(namelen);
  strcpy(filename,filename_gdb.get());
  if (retval != 0)
    tricore_vio_set_result (-1, EIO);
  else
    {
      retval = unlink (filename);
      tricore_vio_set_result (retval, errno);
    }

  if (namelen > 0)
    free (filename);
}

/* See if PC points to the beginning of the ___virtio function.  If not,
   return 0, otherwise register %d12 contains the number of the system
   call to be performed.  Dispatch and execute it, then return 1.  */

int tricore_vio (void)
{
  CORE_ADDR pc;
  int syscall;
  struct regcache *regcache = get_current_regcache ();
  LONGEST value;
  ULONGEST uvalue;
  regcache_cooked_read_unsigned (regcache,TRICORE_PC_REGNUM,&uvalue);
  pc=(CORE_ADDR) uvalue;
  if (tricore_virtio_addr == (CORE_ADDR) -1)
    {
      /* This happens if the executable either doesn't contain the
         ___virtio function, or if it doesn't contain symbol information.
         In the latter case, we check for a magic number before the PC
         to set tricore_virtio_addr to the correct value.  */
      gdb_byte buf[6];

      if (target_read_memory (pc - 4, buf, 6))
      {
    	  return 0;
      }
      /* the value is hard encoded in __virtio_dummy_hnd 0x5f 0x76 0x69 0x6f 0x0 0xa0 */
      if (memcmp ((const void *) buf, (const void *) "_vio\0\xa0", 6))
      {
    	  return 0;
      }
      else
        tricore_virtio_addr = pc;
    }

  if (pc != tricore_virtio_addr)
    return 0;
  regcache_cooked_write_unsigned (regcache,TRICORE_PC_REGNUM,pc+2);

  regcache_cooked_read_signed (regcache,TRICORE_D12_REGNUM,&value);
  syscall=(int) value;
  switch (syscall)
    {
    case SYS__OPEN: tricore_vio_open_creat (1); break;
    case SYS__CLOSE: tricore_vio_close (); break;
    case SYS__LSEEK: tricore_vio_lseek (); break;
    case SYS__READ: tricore_vio_read (); break;
    case SYS__WRITE: tricore_vio_write (); break;
    case SYS__CREAT: tricore_vio_open_creat (0); break;
    case SYS__UNLINK: tricore_vio_unlink (); break;

    case SYS__STAT:
    case SYS__FSTAT:
    case SYS__GETTIME:
    default: tricore_vio_set_result (-1, ENOSYS);
    }
  return 1;
}

#else /* !VIRTUAL_IO */

void tricore_vio_init (void)
{
}

int
tricore_vio (CORE_ADDR pc)
{
  return 0;
}
#endif /* !VIRTUAL_IO */


void _initialize_tricore_tdep ();
void
_initialize_tricore_tdep ()
{
  register_gdbarch_init (bfd_arch_tricore, tricore_gdbarch_init);

  /* Debug this files internals.  */
  add_setshow_zuinteger_cmd ("tricore", class_maintenance,
			     &tricore_debug, _("\
Set tricore debugging."), _("\
Show tricore debugging."), _("\
When non-zero (level=1,2), tricore specific debugging is enabled."),
			     NULL,
			     NULL,
			     &setdebuglist, &showdebuglist);

}
