/**
 * Joern 4.x PHP XSS taint analysis script.
 * Run: joern --script xss_taint.sc --param cpgFile=<path> --param outFile=<path>
 *
 * Joern 4.x uses flatgraph (not overflowdb) — overflowdb.traversal._ is removed.
 */

import io.joern.dataflowengineoss.language._
import io.joern.dataflowengineoss.queryengine.EngineContext
import io.joern.dataflowengineoss.DefaultSemantics
import upickle.default.{ReadWriter, macroRW, write => uwrite}

@main def execMain(
  cpgFile: String = "magento.bin",
  outFile: String = "joern_xss.json"
): Unit = {

importCpg(cpgFile)

implicit val engineContext: EngineContext = EngineContext(DefaultSemantics())

// --- SOURCES ---
val requestInputMethods = List(
  "getParam", "getParams",
  "getPost", "getQuery",
  "getContent", "getBodyParams",
  "getHeader", "getHeaders",
  "getCookie", "getPathInfo",
  "getRequestUri", "getServer"
)

val superglobals = List("_GET", "_POST", "_REQUEST", "_COOKIE", "_FILES", "_SERVER")

val outputFunctions    = List("echo", "print", "printf", "fprintf", "vprintf")
val blockRenderMethods = List("_toHtml", "toHtml", "getChildHtml")

// Count without consuming the traversals used for flow computation
val sourceCount = cpg.call.nameExact(requestInputMethods: _*).size +
                  cpg.identifier.nameExact(superglobals: _*).size
val sinkCount   = cpg.call.nameExact(outputFunctions: _*).size +
                  cpg.call.nameExact(blockRenderMethods: _*).size +
                  cpg.call.name("header").size

println(s"[*] Sources found: $sourceCount")
println(s"[*] Sinks found:   $sinkCount")
println("[*] Computing taint flows...")

// Fresh traversals for the actual flow computation — not consumed above
def sources = cpg.call.nameExact(requestInputMethods: _*) ++
              cpg.identifier.nameExact(superglobals: _*)
def sinks   = cpg.call.nameExact(outputFunctions: _*) ++
              cpg.call.nameExact(blockRenderMethods: _*) ++
              cpg.call.name("header")
println("[*] Computing taint flows...")

case class FlowStep(
  file: String,
  lineNumber: Int,
  code: String,
  nodeType: String
)

case class TaintFinding(
  id: Int,
  source: String,
  sourceFile: String,
  sourceLine: Int,
  sink: String,
  sinkFile: String,
  sinkLine: Int,
  pathLength: Int,
  pathSteps: List[FlowStep]
)

implicit val flowStepRw: ReadWriter[FlowStep] = macroRW
implicit val taintFindingRw: ReadWriter[TaintFinding] = macroRW

val flows = sinks.reachableByFlows(sources).l

println(s"[*] Raw flows found: ${flows.size}")

var findings = List.empty[TaintFinding]
var id = 0

flows.foreach { flow =>
  val elements = flow.elements
  if (elements.nonEmpty) {
    val sourceNode = elements.head
    val sinkNode   = elements.last

    val steps = elements.map { node =>
      FlowStep(
        file       = node.file.name.headOption.getOrElse("<unknown>"),
        lineNumber = node.lineNumber.getOrElse(-1),
        code       = node.code.take(200).replaceAll("\\s+", " ").trim,
        nodeType   = node.getClass.getSimpleName
      )
    }.toList

    id += 1
    findings = findings :+ TaintFinding(
      id         = id,
      source     = sourceNode.code.take(200).trim,
      sourceFile = sourceNode.file.name.headOption.getOrElse("<unknown>"),
      sourceLine = sourceNode.lineNumber.getOrElse(-1),
      sink       = sinkNode.code.take(200).trim,
      sinkFile   = sinkNode.file.name.headOption.getOrElse("<unknown>"),
      sinkLine   = sinkNode.lineNumber.getOrElse(-1),
      pathLength = elements.size,
      pathSteps  = steps
    )
  }
}

val json = uwrite(findings, indent = 2)
os.write.over(os.Path(outFile), json)

println(s"[+] Wrote ${findings.size} flows to $outFile")

val bySink = findings.groupBy(_.sink.split("\\(")(0).trim.take(30))
bySink.toSeq.sortBy(-_._2.size).take(15).foreach { case (sinkCode, fs) =>
  println(f"  ${fs.size}%4d flows -> $sinkCode")
}

findings.take(3).foreach { f =>
  println(s"\n--- Flow #${f.id}: ${f.sourceFile}:${f.sourceLine} -> ${f.sinkFile}:${f.sinkLine} ---")
  f.pathSteps.foreach { s =>
    println(s"  [${s.nodeType}] ${s.file}:${s.lineNumber}  ${s.code.take(80)}")
  }
}

} // end execMain
