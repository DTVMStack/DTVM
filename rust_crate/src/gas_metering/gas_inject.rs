// Copyright (C) 2021-2025 the DTVM authors. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module is used to instrument a Wasm module with the gas metering code.
//!
//! The primary public interface is the [`inject`] function which transforms a given
//! module into one that charges gas for code to be executed. See function documentation for usage
//! and details.

extern crate alloc;

use alloc::{vec, vec::Vec};
use core::{cmp::min, mem, num::NonZeroU32};
use parity_wasm::{
    builder,
    elements::{self, Instruction, ValueType},
};

/// An interface that describes instruction costs.
pub trait Rules {
    /// Returns the cost for the passed `instruction`.
    ///
    /// Returning `None` makes the gas instrumention end with an error. This is meant
    /// as a way to have a partial rule set where any instruction that is not specifed
    /// is considered as forbidden.
    fn instruction_cost(&self, instruction: &Instruction) -> Option<u32>;

    /// Returns the costs for growing the memory using the `memory.grow` instruction.
    ///
    /// Please note that these costs are in addition to the costs specified by `instruction_cost`
    /// for the `memory.grow` instruction. Those are meant as dynamic costs which take the
    /// amount of pages that the memory is grown by into consideration. This is not possible
    /// using `instruction_cost` because those costs depend on the stack and must be injected as
    /// code into the function calling `memory.grow`. Therefore returning anything but
    /// [`MemoryGrowCost::Free`] introduces some overhead to the `memory.grow` instruction.
    fn memory_grow_cost(&self) -> MemoryGrowCost;

    /// A surcharge cost to calling a function that is added per local of that function.
    fn call_per_local_cost(&self) -> u32;
}

/// Dynamic costs for memory growth.
#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum MemoryGrowCost {
    /// Skip per page charge.
    ///
    /// # Note
    ///
    /// This makes sense when the amount of pages that a module is allowed to use is limited
    /// to a rather small number by static validation. In that case it is viable to
    /// benchmark the costs of `memory.grow` as the worst case (growing to to the maximum
    /// number of pages).
    Free,
    /// Charge the specified amount for each page that the memory is grown by.
    Linear(NonZeroU32),
}

impl MemoryGrowCost {
    /// True iff memory growths code needs to be injected.
    fn enabled(&self) -> bool {
        match self {
            Self::Free => false,
            Self::Linear(_) => true,
        }
    }
}

/// A type that implements [`Rules`] so that every instruction costs the same.
///
/// This is a simplification that is mostly useful for development and testing.
///
/// # Note
///
/// In a production environment it usually makes no sense to assign every instruction
/// the same cost. A proper implemention of [`Rules`] should be provided that is probably
/// created by benchmarking.
pub struct ConstantCostRules {
    instruction_cost: u32,
    memory_grow_cost: u32,
    call_per_local_cost: u32,
}

impl ConstantCostRules {
    /// Create a new [`ConstantCostRules`].
    ///
    /// Uses `instruction_cost` for every instruction and `memory_grow_cost` to dynamically
    /// meter the memory growth instruction.
    pub fn new(instruction_cost: u32, memory_grow_cost: u32, call_per_local_cost: u32) -> Self {
        Self {
            instruction_cost,
            memory_grow_cost,
            call_per_local_cost,
        }
    }
}

impl Default for ConstantCostRules {
    /// Uses instruction cost of `1` and disables memory growth instrumentation.
    fn default() -> Self {
        Self {
            instruction_cost: 1,
            memory_grow_cost: 0,
            call_per_local_cost: 1,
        }
    }
}

impl Rules for ConstantCostRules {
    fn instruction_cost(&self, _: &Instruction) -> Option<u32> {
        Some(self.instruction_cost)
    }

    fn memory_grow_cost(&self) -> MemoryGrowCost {
        NonZeroU32::new(self.memory_grow_cost).map_or(MemoryGrowCost::Free, MemoryGrowCost::Linear)
    }

    fn call_per_local_cost(&self) -> u32 {
        self.call_per_local_cost
    }
}

/// Transforms a given module into one that tracks the gas charged during its execution.
///
/// The output module uses the `gas` function to track the gas spent. The function could be either
/// an imported or a local one modifying a mutable global. The argument is the amount of gas
/// required to continue execution. The execution engine is meant to keep track of the total amount
/// of gas used and trap or otherwise halt execution of the runtime if the gas usage exceeds some
/// allowed limit.
///
/// The body of each function of the original module is divided into metered blocks, and the calls
/// to charge gas are inserted at the beginning of every such block of code. A metered block is
/// defined so that, unless there is a trap, either all of the instructions are executed or none
/// are. These are similar to basic blocks in a control flow graph, except that in some cases
/// multiple basic blocks can be merged into a single metered block. This is the case if any path
/// through the control flow graph containing one basic block also contains another.
///
/// Charging gas at the beginning of each metered block ensures that 1) all instructions
/// executed are already paid for, 2) instructions that will not be executed are not charged for
/// unless execution traps, and 3) the number of calls to `gas` is minimized. The corollary is
/// that modules instrumented with this metering code may charge gas for instructions not
/// executed in the event of a trap.
///
/// Additionally, each `memory.grow` instruction found in the module is instrumented to first
/// make a call to charge gas for the additional pages requested. This cannot be done as part of
/// the block level gas charges as the gas cost is not static and depends on the stack argument
/// to `memory.grow`.
///
/// The above transformations are performed for every function body defined in the module. This
/// function also rewrites all function indices references by code, table elements, etc., since
/// the addition of an imported functions changes the indices of module-defined functions. If
/// the module has a `NameSection`, added by calling `parse_names`, the indices will also be
/// updated.
///
/// Syncronizing the amount of gas charged with the execution engine can be done in two ways. The
/// first way is by calling the imported `gas` host function, see [`host_function`] for details. The
/// second way is by using a local `gas` function together with a mutable global, see
/// [`mutable_global`] for details.
///
/// This routine runs in time linear in the size of the input module.
///
/// The function fails if the module contains any operation forbidden by gas rule set, returning
/// the original module as an `Err`.
pub fn inject<R: Rules>(
    module: elements::Module,
    rules: &R,
) -> Result<elements::Module, elements::Module> {
    let functions_space = module.functions_space() as u32;

    let mut mbuilder = builder::from_module(module.clone());

    // Inject the export for `__instrumented_use_gas`
    let gas_func_sig = builder::SignatureBuilder::new()
        .with_param(ValueType::I64)
        .build_sig();

    let function = builder::FunctionBuilder::new()
        .with_signature(gas_func_sig)
        .body()
        .with_instructions(elements::Instructions::new(vec![Instruction::End]))
        .build()
        .build();

    // Inject local gas function
    mbuilder.push_function(function);

    // Inject the export entry for the gas counting function
    let gas_func_idx = functions_space;
    mbuilder.push_export(
        builder::export()
            .field("__instrumented_use_gas")
            .internal()
            .func(gas_func_idx)
            .build(),
    );

    // Gas function cost is 0 since it's an empty function and its cost is self-accounted.
    let gas_fn_cost = 0;
    let total_func = functions_space + 1;

    // We need the built the module for making injections to its blocks
    let mut resulting_module = mbuilder.build();

    let mut need_grow_counter = false;
    let mut result = Ok(());
    // Iterate over module sections and perform needed transformations.
    'outer: for section in resulting_module.sections_mut() {
        match section {
            elements::Section::Code(code_section) => {
                // Don't inject counters to the gas function itself, which is the last one.
                let len = code_section.bodies().len();
                let injection_targets = &mut code_section.bodies_mut()[..len - 1];

                for func_body in injection_targets {
                    result = func_body
                        .locals()
                        .iter()
                        .try_fold(0u32, |count, val_type| count.checked_add(val_type.count()))
                        .ok_or(())
                        .and_then(|locals_count| {
                            inject_counter(
                                func_body.code_mut(),
                                gas_fn_cost,
                                locals_count,
                                rules,
                                gas_func_idx,
                            )
                        });
                    if result.is_err() {
                        break 'outer;
                    }
                    if rules.memory_grow_cost().enabled()
                        && inject_grow_counter(func_body.code_mut(), total_func) > 0
                    {
                        need_grow_counter = true;
                    }
                }
            }
            // Since we are adding a function to the end of the function space,
            // we don't need to adjust any indices.
            _ => {}
        }
    }

    result.map_err(|_| module)?;

    if need_grow_counter {
        Ok(add_grow_counter(resulting_module, rules, gas_func_idx))
    } else {
        Ok(resulting_module)
    }
}

/// A control flow block is opened with the `block`, `loop`, and `if` instructions and is closed
/// with `end`. Each block implicitly defines a new label. The control blocks form a stack during
/// program execution.
///
/// An example of block:
///
/// ```wasm
/// loop
///   i32.const 1
///   local.get 0
///   i32.sub
///   local.tee 0
///   br_if 0
/// end
/// ```
///
/// The start of the block is `i32.const 1`.
#[derive(Debug)]
struct ControlBlock {
    /// The lowest control stack index corresponding to a forward jump targeted by a br, br_if, or
    /// br_table instruction within this control block. The index must refer to a control block
    /// that is not a loop, meaning it is a forward jump. Given the way Wasm control flow is
    /// structured, the lowest index on the stack represents the furthest forward branch target.
    ///
    /// This value will always be at most the index of the block itself, even if there is no
    /// explicit br instruction targeting this control block. This does not affect how the value is
    /// used in the metering algorithm.
    lowest_forward_br_target: usize,

    /// The active metering block that new instructions contribute a gas cost towards.
    active_metered_block: MeteredBlock,

    /// Whether the control block is a loop. Loops have the distinguishing feature that branches to
    /// them jump to the beginning of the block, not the end as with the other control blocks.
    is_loop: bool,
}

/// A block of code that metering instructions will be inserted at the beginning of. Metered blocks
/// are constructed with the property that, in the absence of any traps, either all instructions in
/// the block are executed or none are.
#[derive(Debug)]
pub(crate) struct MeteredBlock {
    /// Index of the first instruction (aka `Opcode`) in the block.
    pub(crate) start_pos: usize,
    /// Sum of costs of all instructions until end of the block.
    pub(crate) cost: u64,
}

/// Counter is used to manage state during the gas metering algorithm implemented by
/// `inject_counter`.
struct Counter {
    /// A stack of control blocks. This stack grows when new control blocks are opened with
    /// `block`, `loop`, and `if` and shrinks when control blocks are closed with `end`. The first
    /// block on the stack corresponds to the function body, not to any labelled block. Therefore
    /// the actual Wasm label index associated with each control block is 1 less than its position
    /// in this stack.
    stack: Vec<ControlBlock>,

    /// A list of metered blocks that have been finalized, meaning they will no longer change.
    finalized_blocks: Vec<MeteredBlock>,
}

impl Counter {
    fn new() -> Counter {
        Counter {
            stack: Vec::new(),
            finalized_blocks: Vec::new(),
        }
    }

    /// Open a new control block. The cursor is the position of the first instruction in the block.
    fn begin_control_block(&mut self, cursor: usize, is_loop: bool) {
        let index = self.stack.len();
        self.stack.push(ControlBlock {
            lowest_forward_br_target: index,
            active_metered_block: MeteredBlock {
                start_pos: cursor,
                cost: 0,
            },
            is_loop,
        })
    }

    /// Close the last control block. The cursor is the position of the final (pseudo-)instruction
    /// in the block.
    fn finalize_control_block(&mut self, cursor: usize) -> Result<(), ()> {
        // This either finalizes the active metered block or merges its cost into the active
        // metered block in the previous control block on the stack.
        self.finalize_metered_block(cursor)?;

        // Pop the control block stack.
        let closing_control_block = self.stack.pop().ok_or(())?;
        let closing_control_index = self.stack.len();

        if self.stack.is_empty() {
            return Ok(());
        }

        // Update the lowest_forward_br_target for the control block now on top of the stack.
        {
            let control_block = self.stack.last_mut().ok_or(())?;
            control_block.lowest_forward_br_target = min(
                control_block.lowest_forward_br_target,
                closing_control_block.lowest_forward_br_target,
            );
        }

        // If there may have been a branch to a lower index, then also finalize the active metered
        // block for the previous control block. Otherwise, finalize it and begin a new one.
        let may_br_out = closing_control_block.lowest_forward_br_target < closing_control_index;
        if may_br_out {
            self.finalize_metered_block(cursor)?;
        }

        Ok(())
    }

    /// Finalize the current active metered block.
    ///
    /// Finalized blocks have final cost which will not change later.
    fn finalize_metered_block(&mut self, cursor: usize) -> Result<(), ()> {
        let closing_metered_block = {
            let control_block = self.stack.last_mut().ok_or(())?;
            mem::replace(
                &mut control_block.active_metered_block,
                MeteredBlock {
                    start_pos: cursor + 1,
                    cost: 0,
                },
            )
        };

        // If the block was opened with a `block`, then its start position will be set to that of
        // the active metered block in the control block one higher on the stack. This is because
        // any instructions between a `block` and the first branch are part of the same basic block
        // as the preceding instruction. In this case, instead of finalizing the block, merge its
        // cost into the other active metered block to avoid injecting unnecessary instructions.
        let last_index = self.stack.len() - 1;
        if last_index > 0 {
            let prev_control_block = self
                .stack
                .get_mut(last_index - 1)
                .expect("last_index is greater than 0; last_index is stack size - 1; qed");
            let prev_metered_block = &mut prev_control_block.active_metered_block;
            if closing_metered_block.start_pos == prev_metered_block.start_pos {
                prev_metered_block.cost = prev_metered_block
                    .cost
                    .checked_add(closing_metered_block.cost)
                    .ok_or(())?;
                return Ok(());
            }
        }

        if closing_metered_block.cost > 0 {
            self.finalized_blocks.push(closing_metered_block);
        }
        Ok(())
    }

    /// Handle a branch instruction in the program. The cursor is the index of the branch
    /// instruction in the program. The indices are the stack positions of the target control
    /// blocks. Recall that the index is 0 for a `return` and relatively indexed from the top of
    /// the stack by the label of `br`, `br_if`, and `br_table` instructions.
    fn branch(&mut self, cursor: usize, indices: &[usize]) -> Result<(), ()> {
        self.finalize_metered_block(cursor)?;

        // Update the lowest_forward_br_target of the current control block.
        for &index in indices {
            let target_is_loop = {
                let target_block = self.stack.get(index).ok_or(())?;
                target_block.is_loop
            };
            if target_is_loop {
                continue;
            }

            let control_block = self.stack.last_mut().ok_or(())?;
            control_block.lowest_forward_br_target =
                min(control_block.lowest_forward_br_target, index);
        }

        Ok(())
    }

    /// Returns the stack index of the active control block. Returns None if stack is empty.
    fn active_control_block_index(&self) -> Option<usize> {
        self.stack.len().checked_sub(1)
    }

    /// Get a reference to the currently active metered block.
    fn active_metered_block(&mut self) -> Result<&mut MeteredBlock, ()> {
        let top_block = self.stack.last_mut().ok_or(())?;
        Ok(&mut top_block.active_metered_block)
    }

    /// Increment the cost of the current block by the specified value.
    fn increment(&mut self, val: u32) -> Result<(), ()> {
        let top_block = self.active_metered_block()?;
        top_block.cost = top_block.cost.checked_add(val.into()).ok_or(())?;
        Ok(())
    }
}

fn inject_grow_counter(instructions: &mut elements::Instructions, grow_counter_func: u32) -> usize {
    use parity_wasm::elements::Instruction::*;
    let mut counter = 0;
    for instruction in instructions.elements_mut() {
        if let GrowMemory(_) = *instruction {
            *instruction = Call(grow_counter_func);
            counter += 1;
        }
    }
    counter
}

fn add_grow_counter<R: Rules>(
    module: elements::Module,
    rules: &R,
    gas_func: u32,
) -> elements::Module {
    use parity_wasm::elements::Instruction::*;

    let cost = match rules.memory_grow_cost() {
        MemoryGrowCost::Free => return module,
        MemoryGrowCost::Linear(val) => val.get(),
    };

    let mut b = builder::from_module(module);
    b.push_function(
        builder::function()
            .signature()
            .with_param(ValueType::I32)
            .with_result(ValueType::I32)
            .build()
            .body()
            .with_instructions(elements::Instructions::new(vec![
                GetLocal(0),
                GetLocal(0),
                I64ExtendUI32,
                I64Const(i64::from(cost)),
                I64Mul,
                // todo: there should be strong guarantee that it does not return anything on
                // stack?
                Call(gas_func),
                GrowMemory(0),
                End,
            ]))
            .build()
            .build(),
    );

    b.build()
}

pub(crate) fn determine_metered_blocks<R: Rules>(
    instructions: &elements::Instructions,
    rules: &R,
    locals_count: u32,
) -> Result<Vec<MeteredBlock>, ()> {
    use parity_wasm::elements::Instruction::*;

    let mut counter = Counter::new();

    // Begin an implicit function (i.e. `func...end`) block.
    counter.begin_control_block(0, false);
    // Add locals initialization cost to the function block.
    let locals_init_cost = rules
        .call_per_local_cost()
        .checked_mul(locals_count)
        .ok_or(())?;
    counter.increment(locals_init_cost)?;

    for cursor in 0..instructions.elements().len() {
        let instruction = &instructions.elements()[cursor];
        let instruction_cost = rules.instruction_cost(instruction).ok_or(())?;
        match instruction {
            Block(_) => {
                counter.increment(instruction_cost)?;

                // Begin new block. The cost of the following opcodes until `end` or `else` will
                // be included into this block. The start position is set to that of the previous
                // active metered block to signal that they should be merged in order to reduce
                // unnecessary metering instructions.
                let top_block_start_pos = counter.active_metered_block()?.start_pos;
                counter.begin_control_block(top_block_start_pos, false);
            }
            If(_) => {
                counter.increment(instruction_cost)?;
                counter.begin_control_block(cursor + 1, false);
            }
            Loop(_) => {
                counter.increment(instruction_cost)?;
                counter.begin_control_block(cursor + 1, true);
            }
            End => {
                counter.finalize_control_block(cursor)?;
            }
            Else => {
                counter.finalize_metered_block(cursor)?;
            }
            Br(label) | BrIf(label) => {
                counter.increment(instruction_cost)?;

                // Label is a relative index into the control stack.
                let active_index = counter.active_control_block_index().ok_or(())?;
                let target_index = active_index.checked_sub(*label as usize).ok_or(())?;
                counter.branch(cursor, &[target_index])?;
            }
            BrTable(br_table_data) => {
                counter.increment(instruction_cost)?;

                let active_index = counter.active_control_block_index().ok_or(())?;
                let target_indices = [br_table_data.default]
                    .iter()
                    .chain(br_table_data.table.iter())
                    .map(|label| active_index.checked_sub(*label as usize))
                    .collect::<Option<Vec<_>>>()
                    .ok_or(())?;
                counter.branch(cursor, &target_indices)?;
            }
            Return => {
                counter.increment(instruction_cost)?;
                counter.branch(cursor, &[0])?;
            }
            _ => {
                // An ordinal non control flow instruction increments the cost of the current block.
                counter.increment(instruction_cost)?;
            }
        }
    }

    counter
        .finalized_blocks
        .sort_unstable_by_key(|block| block.start_pos);
    Ok(counter.finalized_blocks)
}

fn inject_counter<R: Rules>(
    instructions: &mut elements::Instructions,
    gas_function_cost: u64,
    locals_count: u32,
    rules: &R,
    gas_func: u32,
) -> Result<(), ()> {
    let blocks = determine_metered_blocks(instructions, rules, locals_count)?;
    insert_metering_calls(instructions, gas_function_cost, blocks, gas_func)
}

// Then insert metering calls into a sequence of instructions given the block locations and costs.
fn insert_metering_calls(
    instructions: &mut elements::Instructions,
    gas_function_cost: u64,
    blocks: Vec<MeteredBlock>,
    gas_func: u32,
) -> Result<(), ()> {
    use parity_wasm::elements::Instruction::*;

    // To do this in linear time, construct a new vector of instructions, copying over old
    // instructions one by one and injecting new ones as required.
    let new_instrs_len = instructions.elements().len() + 2 * blocks.len();
    let original_instrs = mem::replace(
        instructions.elements_mut(),
        Vec::with_capacity(new_instrs_len),
    );
    let new_instrs = instructions.elements_mut();

    let mut block_iter = blocks.into_iter().peekable();
    for (original_pos, instr) in original_instrs.into_iter().enumerate() {
        // If there the next block starts at this position, inject metering instructions.
        let used_block = if let Some(block) = block_iter.peek() {
            if block.start_pos == original_pos {
                new_instrs.push(I64Const(
                    (block.cost.checked_add(gas_function_cost).ok_or(())?) as i64,
                ));
                new_instrs.push(Call(gas_func));
                true
            } else {
                false
            }
        } else {
            false
        };

        if used_block {
            block_iter.next();
        }

        // Copy over the original instruction.
        new_instrs.push(instr);
    }

    if block_iter.next().is_some() {
        return Err(());
    }

    Ok(())
}
