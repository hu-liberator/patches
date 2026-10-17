package app.template.patches.shared

import app.morphe.patcher.extensions.InstructionExtensions.instructions
import app.morphe.patcher.extensions.InstructionExtensions.replaceInstruction
import app.morphe.patcher.util.proxy.mutableTypes.MutableMethod
import com.android.tools.smali.dexlib2.Opcode
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction11x
import com.android.tools.smali.dexlib2.iface.instruction.formats.Instruction21c
import com.android.tools.smali.dexlib2.iface.reference.TypeReference

/**
 * dexlib2 opcodes for the inline data-table pseudo-instructions. These are not
 * executable code; a `packed-switch`/`sparse-switch` references its payload by
 * offset, and `fill-array-data` references an array payload. They are always
 * emitted after a control-flow terminator (return/throw/goto) so that they are
 * never reachable by fall-through -- if they were, the verifier rejects the
 * class with "encountered data table in instruction stream".
 */
private val DATA_TABLE_PAYLOAD_OPCODES = setOf(
    Opcode.PACKED_SWITCH_PAYLOAD,
    Opcode.SPARSE_SWITCH_PAYLOAD,
    Opcode.ARRAY_PAYLOAD,
)

/**
 * Neutralizes every `throw` instruction in [method] whose thrown value was
 * constructed via `new-instance ..., [exceptionType]` (identified by the
 * nearest preceding new-instance targeting the same register), leaving
 * everything else in the method -- including throws of other exception types
 * and any unrelated code sharing the method -- untouched.
 *
 * Each matching `throw` is neutralized **in place** with a single-code-unit
 * replacement, never deleted. `throw` (format 11x), `nop` (10x), `return-void`
 * (10x) and `return-object`/`return`/`return-wide` (11x) are all exactly one
 * code unit, so no instruction address ever shifts -- a deliberate precaution
 * for the control-flow-flattened methods this is used on, where a packed-switch
 * dispatch can jump directly at a specific instruction's address (deleting or
 * inserting instructions here corrupted Qa.u0.m()'s packed-switch and caused a
 * VerifyError -- see git history).
 *
 * The replacement is normally `nop`, so execution simply falls through past the
 * (now removed) throw into the code that followed it -- which for these shared,
 * switch-dispatched methods is the intended "pretend the check passed and carry
 * on" behavior, and for Q2.c.onReceive() deliberately preserves the legitimate
 * post-check dispatch rather than skipping it.
 *
 * **Exception:** a `throw` can itself be the control-flow terminator that sits
 * immediately before an inline data-table payload (or be the method's very last
 * instruction). `nop`-ing it there would let control fall through into the data
 * table (or off the end of the method), which the verifier rejects at class load
 * with `VerifyError: ... encountered data table in instruction stream`. This was
 * observed on hu.mav.emmapp 2.6.13-prod, where R8 placed the Play Integrity
 * verdict method's last `throw new SecurityException()` (Lc8/F;->u, offset 0x5d1)
 * directly before its `:pswitch_data_0` payload (0x5d2 -- the exact offset in the
 * crash). In that case the throw is replaced with a same-size `return`
 * terminator instead: it still prevents the exception being thrown, and keeps the
 * payload unreachable by fall-through so the class verifies. For the
 * Object-returning verdict method this returns the just-constructed exception
 * object (harmless: that switch case is made unreachable at runtime by
 * DisablePlayIntegrityRequestPatch, and the only requirement here is that the
 * class verify); for a void method it becomes `return-void`.
 */
fun neutralizeExceptionThrows(method: MutableMethod, exceptionType: String) {
    val instructions = method.instructions

    // Collect targets (index + register + whether a nop here would be illegal)
    // up front, before mutating anything -- every replacement is one code unit,
    // so indices stay valid, but snapshotting keeps the fall-through check based
    // on the original instruction stream.
    val targets = instructions.indices.mapNotNull { i ->
        val insn = instructions[i]
        if (insn.opcode != Opcode.THROW) return@mapNotNull null
        val throwReg = (insn as Instruction11x).registerA

        val nearestNewInstance = (i - 1 downTo maxOf(0, i - 15))
            .map { j -> instructions[j] }
            .firstOrNull { it.opcode == Opcode.NEW_INSTANCE && (it as Instruction21c).registerA == throwReg }
            as Instruction21c?

        if (nearestNewInstance == null ||
            (nearestNewInstance.reference as TypeReference).type != exceptionType
        ) {
            return@mapNotNull null
        }

        val next = instructions.getOrNull(i + 1)
        val nopWouldFallThroughIntoData = next == null || next.opcode in DATA_TABLE_PAYLOAD_OPCODES
        Triple(i, throwReg, nopWouldFallThroughIntoData)
    }

    targets.forEach { (index, throwReg, nopWouldFallThroughIntoData) ->
        val replacement = if (!nopWouldFallThroughIntoData) {
            "nop"
        } else {
            val returnType = method.returnType
            when {
                returnType == "V" -> "return-void"
                returnType.startsWith("L") || returnType.startsWith("[") -> "return-object v$throwReg"
                else -> error(
                    "neutralizeExceptionThrows: a $exceptionType throw in " +
                        "${method.definingClass}->${method.name} sits immediately before a data-table " +
                        "payload (or at the method's end) and cannot be replaced with nop, but the method " +
                        "returns the primitive type '$returnType', so no object register is available to " +
                        "return. This case hasn't occurred in practice; handle it explicitly if it does.",
                )
            }
        }
        method.replaceInstruction(index, replacement)
    }
}
