module libssh.mix;

package:

import std.array : appender;
import std.algorithm : map;
import std.string : lineSplitter, strip, startsWith;
import std.range : put;

string appendToAllLines(string lines, string suffix, string g_prefix, string g_suffix)
{
    auto buf = appender!string;

    if (g_prefix.length)
    {
        put(buf, g_prefix);
        put(buf, "\n");
    }

    foreach (line; lines.lineSplitter.map!strip)
    {
        if (line.startsWith("//")) // comment
        {
            put(buf, line);
        }
        else if (line.startsWith("%")) // not append
        {
            put(buf, line[1..$]);
        }
        else if (line.length)
        {
            put(buf, line);
            put(buf, suffix);
        }
        put(buf, "\n");
    }

    put(buf, g_suffix);

    return buf.data;
}

unittest
{
    enum src = `
    int foo(int a, int b)

    // comment

    %version (Windows) {}
    %else {
        int bar(some / random % string)
    %}
    `;

    enum r1 = appendToAllLines(src, ";", "{", "}");
    enum e1 = `{

int foo(int a, int b);

// comment

version (Windows) {}
else {
int bar(some / random % string);
}

}`;

    static assert(r1 == e1);

    enum r2 = appendToAllLines(src, "{ mixin(rtLib); }", "", "");
    enum e2 = `
int foo(int a, int b){ mixin(rtLib); }

// comment

version (Windows) {}
else {
int bar(some / random % string){ mixin(rtLib); }
}

`;

    static assert(r2 == e2);
}

string pastFunctions(string input, string libname="lib")
{
    version (libssh_rtload)
        return appendToAllLines(input, "{ mixin(SSLL_CALL); }",
                    `mixin SSLL_INIT; @api("`~libname~`") {`, `}`);
    else
        return appendToAllLines(input, ";", "extern (C) {", "}");
}