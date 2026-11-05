import { describe, expect, it } from "vitest";
import { parseSegments, isWriteRedirect, ParseFailure } from "./segments.ts";

describe("parseSegments", () => {
  it("splits && ; and pipes into separate segments", () => {
    expect(parseSegments("a --x 1 && b ; c | d")).toHaveLength(4);
  });

  it("extracts literal words and verbs", () => {
    const segs = parseSegments("cat 'my file.txt'");
    expect(segs[0].cmds[0].verb).toEqual({ text: "cat", literal: true });
    expect(segs[0].cmds[0].args[0]).toEqual({ text: "my file.txt", literal: true });
  });

  it("marks expansion words non-literal and segment undecidable", () => {
    const segs = parseSegments("rm -rf $HOME/x");
    expect(segs[0].undecidable).toBe(true);
    expect(segs[0].cmds[0].args[1].literal).toBe(false);
  });

  it("treats indirection verbs as undecidable ($R=rm)", () => {
    const segs = parseSegments("R=rm; $R -rf /tmp/x");
    expect(segs[1].cmds[0].verb.literal).toBe(false);
    expect(segs[1].undecidable).toBe(true);
  });

  it("captures assignments", () => {
    const segs = parseSegments("FOO=/tmp/x; echo $FOO");
    expect(segs[0].assignments[0]).toMatchObject({ name: "FOO" });
    expect(segs[0].assignments[0].value).toEqual({ text: "/tmp/x", literal: true });
  });

  it("extracts write redirects with targets", () => {
    const segs = parseSegments("echo x > /tmp/f 2>> e.txt");
    const r = segs[0].redirects;
    expect(r).toHaveLength(2);
    expect(r[0]).toMatchObject({ op: ">", target: { text: "/tmp/f", literal: true } });
    expect(isWriteRedirect(r[0])).toBe(true);
    expect(isWriteRedirect(r[1])).toBe(true); // 2>> e.txt is a file append
  });

  it("does not treat fd dup as write redirect", () => {
    const segs = parseSegments("cmd 2>&1 > /dev/null");
    expect(segs[0].redirects.filter(isWriteRedirect)).toHaveLength(1);
  });

  it("heredoc is not a write redirect", () => {
    const segs = parseSegments("cat <<EOF\nhi\nEOF");
    expect(segs[0].redirects.filter(isWriteRedirect)).toHaveLength(0);
  });

  it("unquoted heredoc marks segment undecidable (body may expand)", () => {
    const segs = parseSegments("cat <<EOF\n$(touch x)\nEOF");
    expect(segs[0].undecidable).toBe(true);
    expect(segs[0].redirects[0].heredocQuoted).toBe(false);
  });

  it("quoted heredoc stays decidable (literal data)", () => {
    const segs = parseSegments("cat <<'EOF'\n$(touch x)\nEOF");
    expect(segs[0].undecidable).toBe(false);
    expect(segs[0].redirects[0].heredocQuoted).toBe(true);
  });

  it(">& file is a write redirect", () => {
    const segs = parseSegments("echo x >& ~/.bashrc");
    expect(segs[0].redirects.filter(isWriteRedirect)).toHaveLength(1);
  });

  it("read redirect exposes its target", () => {
    const segs = parseSegments("wc -c < ~/.ssh/id_ed25519");
    const r = segs[0].redirects[0];
    expect(r.op).toBe("<");
    expect(r.target).toEqual({ text: "~/.ssh/id_ed25519", literal: true, heredocQuoted: undefined });
  });

  it("command substitution marks undecidable", () => {
    const segs = parseSegments("rm -rf $(cat list.txt)");
    expect(segs[0].undecidable).toBe(true);
  });

  it("throws ParseFailure on garbage", () => {
    expect(() => parseSegments('echo "unclosed')).toThrow(ParseFailure);
    expect(() => parseSegments("echo | | bar")).toThrow(ParseFailure);
  });
});
