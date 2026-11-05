import { parse } from "@aliou/sh";

/** A shell word reduced to text + whether it is statically known. */
export interface XWord {
  text: string;
  literal: boolean;
}

export interface XRedirect {
  op: string;
  target: XWord;
  /** Heredoc delimiter was quoted (`<<'EOF'`) ⇒ body is literal data. */
  heredocQuoted?: boolean;
}

export interface XCmd {
  verb: XWord;
  args: XWord[];
}

export interface XAssign {
  name: string;
  value: XWord;
}

export interface Segment {
  index: number;
  cmds: XCmd[];
  redirects: XRedirect[];
  assignments: XAssign[];
  /** Any expansion/substitution was found anywhere in this segment. */
  undecidable: boolean;
}

export class ParseFailure extends Error {}

function isHeredocOp(op: unknown): boolean {
  return op === "<<" || op === "<<-";
}

const LITERAL_PARTS = new Set(["Literal", "SglQuoted"]);

function partText(part: any, expandable: { v: boolean }): string {
  switch (part?.type) {
    case "Literal":
    case "SglQuoted":
      return String(part.value ?? "");
    case "DblQuoted":
      return (part.parts ?? []).map((p: any) => partText(p, expandable)).join("");
    case "ParamExp":
      expandable.v = true;
      return `$${part.param?.value ?? "?"}`;
    case "Tilde":
      // statically known: ~/x resolves via homedir at resolve time
      return String(part.value ?? "~");
    default:
      // CmdSubst, ProcSubst, ArithExp, BraceExp, ExtGlob, Tilde, ...
      expandable.v = true;
      return `$(${part?.type ?? "?"})`;
  }
}

function word(w: any): XWord {
  const expandable = { v: false };
  const text = (w?.parts ?? [])
    .map((p: any) => partText(p, expandable))
    .join("");
  return { text, literal: !expandable.v };
}

const WRITE_REDIRECT_OPS = new Set([">", ">>", ">|", "<>", ">&", "&>", "&>>", ">"]);

export function isHeredoc(r: XRedirect): boolean {
  return r.op === "<<" || r.op === "<<-";
}

export function isWriteRedirect(r: XRedirect): boolean {
  // `>&2`-style fd dups carry no file target; treat words that are pure
  // digits/& as fd dup and not a file write.
  if (/^&?\d+$/.test(r.target.text)) return false;
  return WRITE_REDIRECT_OPS.has(r.op);
}

interface Collector {
  seg: Segment | null;
}

function walk(node: any, c: Collector, out: Segment[]): void {
  if (!node || typeof node !== "object") return;
  const t = node.type;

  if (t === "SimpleCommand") {
    const words: XWord[] = (node.words ?? []).map(word);
    const seg: Segment = {
      index: out.length,
      cmds: words.length
        ? [{ verb: words[0], args: words.slice(1) }]
        : [],
      redirects: (node.redirects ?? [])
        .filter((r: any) => r?.target)
        .map((r: any) => ({
          op: String(r.op ?? ""),
          target: word(r.target),
          heredocQuoted: isHeredocOp(r.op)
            ? (r.target?.parts ?? []).every((p: any) => p?.type === "SglQuoted" || p?.type === "DblQuoted")
            : undefined,
        })),
      assignments: (node.assignments ?? []).map((a: any) => ({
        name: String(a?.name ?? ""),
        value: word(a?.value ?? { parts: [] }),
      })),
      undecidable: false,
    };
    seg.undecidable =
      seg.cmds.some((x) => !x.verb.literal) ||
      seg.cmds.some((x) => x.args.some((a) => !a.literal)) ||
      seg.redirects.some((r) => !r.target.literal) ||
      // Unquoted-delimiter heredoc: the parser cannot see inside the body,
      // and the shell WILL expand it — contained, never "safe".
      seg.redirects.some((r) => isHeredoc(r) && r.heredocQuoted === false);
    out.push(seg);
    c.seg = seg;
    // heredoc bodies: no file target; ignore content.
    return;
  }

  // Nested command inside a substitution found while collecting words:
  // recurse generically; any SimpleCommand found joins the current segment.
  if (t === "Word" || t === undefined) {
    for (const p of node.parts ?? []) walkParts(p, c, out);
    return;
  }
  for (const k of Object.keys(node)) {
    const v = (node as Record<string, unknown>)[k];
    if (Array.isArray(v)) v.forEach((x) => walk(x, c, out));
    else if (v && typeof v === "object") walk(v, c, out);
  }
}

function walkParts(part: any, c: Collector, out: Segment[]): void {
  if (!part || typeof part !== "object") return;
  if (part.type === "SimpleCommand") {
    walk(part, c, out);
    // Merge into current segment: reclassify nested cmd as part of it.
    const nested = out.pop()!;
    const cur = c.seg;
    if (cur) {
      cur.cmds.push(...nested.cmds);
      cur.redirects.push(...nested.redirects);
      cur.undecidable = cur.undecidable || nested.undecidable;
    } else {
      out.push(nested);
      c.seg = nested;
    }
    return;
  }
  for (const k of Object.keys(part)) {
    const v = (part as Record<string, unknown>)[k];
    if (Array.isArray(v)) v.forEach((x) => walkParts(x, c, out));
    else if (v && typeof v === "object") walkParts(v, c, out);
  }
}

/**
 * Parse a command string into linearly-ordered segments. Every SimpleCommand
 * at statement/pipeline level starts a new segment; commands nested inside
 * command/process substitutions are merged into the enclosing segment (their
 * effects belong to it). Throws ParseFailure on invalid shell — callers must
 * treat that as UNDECIDABLE (sandbox or ask), never as safe.
 */
export function parseSegments(command: string): Segment[] {
  let ast: unknown;
  try {
    ast = (parse as (s: string) => { ast: unknown })(command).ast;
  } catch (e) {
    throw new ParseFailure(String(e));
  }
  const out: Segment[] = [];
  walk(ast, { seg: null }, out);
  return out;
}
