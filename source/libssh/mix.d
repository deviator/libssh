module libssh.mix;

import std.array : appender;
import std.string : lineSplitter, strip;
import std.range : put;

string appendToAllLines(string lines, string suffix)
{
    auto buf = appender!string;

    foreach (line; lines.lineSplitter)
    {
        if (line.startsWith("//")) // comment
        {
            put(buf, line);
        }
        else if (line.startsWith("%")) // not append
        {
            put(buf, line[1..$]);
        }
        else if (line.strip.length)
        {
            put(buf, line);
            put(buf, suffix);
        }
        put(buf, "\n");
    }

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

    static assert(appendToAllLines(src, ";") ==
    `
    int foo(int a, int b);

    // comment

    version (Windows) {}
    else {
        int bar(some / random % string);
    }
    `);

    static assert(appendToAllLines(src, "{ mixin(rtLib); }") ==
    `
    int foo(int a, int b){ mixin(rtLib); }

    // comment

    version (Windows) {}
    else {
        int bar(some / random % string){ mixin(rtLib); }
    }
    `);
}