path = r'D:\Github项目\PyAegis\pyaegis\cli.py'
with open(path, 'r', encoding='utf-8') as f:
    content = f.read()

old_text = '''    args = _merge_config(
        args,
        config,
        keys=["rules", "format", "workers", "timeout", "severity"],
    )
    rules_path = args.rules or _default_rules_path()'''

new_text = '''    args = _merge_config(
        args,
        config,
        keys=["rules", "ruleset", "format", "workers", "timeout", "severity"],
    )

    # Determine rules path: --rules takes precedence over --ruleset
    rules_path = None
    if args.rules:
        rules_path = args.rules
    elif getattr(args, "ruleset", None):
        rules_path = _resolve_ruleset(args.ruleset)
        if not rules_path:
            available = ", ".join(sorted(_available_rulesets().keys()))
            sys.stderr.write(
                f"Unknown ruleset: {args.ruleset}. Available rulesets: {available}\\n"
            )
            return 2

    if not rules_path:
        rules_path = _default_rules_path()'''

if old_text not in content:
    # Try with different line endings
    old_text_crlf = old_text.replace('\n', '\r\n')
    new_text_crlf = new_text.replace('\n', '\r\n')
    
    if old_text_crlf in content:
        content = content.replace(old_text_crlf, new_text_crlf)
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        print('SUCCESS (CRLF)')
    else:
        print('OLD TEXT NOT FOUND (tried both LF and CRLF)')
        # Debug: print what's actually there
        import re
        match = re.search(r'args = _merge_config\([^)]+keys=\[[^\]]+\][^)]+\)\s+rules_path =', content)
        if match:
            print(f'Found similar pattern at position {match.start()}:')
            print(repr(content[match.start():match.start()+200]))
else:
    content = content.replace(old_text, new_text)
    with open(path, 'w', encoding='utf-8') as f:
        f.write(content)
    print('SUCCESS (LF)')
