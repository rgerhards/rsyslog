version=2
rule=unset-bug:%[
    { "type": "char-to",    "name": "kfoo", "extradata": " " },
    { "type": "whitespace" },
    { "type": "char-to",    "name": "ku1", "extradata": " " },
    { "type": "whitespace" },
    { "type": "char-to",    "name": "kbar", "extradata": " " },
    { "type": "whitespace" },
    { "type": "char-to",    "name": "kfoo2", "extradata": " " },
    { "type": "whitespace" },
    { "type": "char-to",    "name": "ku2", "extradata": " " },
    { "type": "whitespace" },

    { "type": "rest" } ]%
